#!/usr/bin/env python3
"""Loopback reverse proxy that makes moto compatible with the Terraform AWS provider.

The AWS SDK for Go v2 (used by the Terraform provider) talks to CloudWatch
using the Smithy RPCv2 CBOR protocol (POST /service/<svc>/operation/<op>).
moto 5.x only implements CloudWatch's awsJson1_0 / query protocols. For
requests carrying ``Smithy-Protocol: rpc-v2-cbor`` this shim:

  1. decodes the CBOR body and re-issues the call to moto as awsJson1_0
     (POST / with X-Amz-Target), keeping the original Authorization header
     so moto still routes by the signing service name;
  2. re-encodes moto's JSON reply as CBOR, using the botocore service model
     so timestamp members become CBOR tag 1.

Every other request is forwarded byte-for-byte.

It is a local-validation helper only: it binds to 127.0.0.1 and is never
deployed.

Usage: moto_cbor_shim.py LISTEN_PORT UPSTREAM_PORT
"""

from __future__ import annotations

import datetime as dt
import http.client
import json
import os
import struct
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import botocore.session

_SESSION = botocore.session.get_session()
_MODELS: dict[str, Any] = {}
HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "content-length", "content-type"}


# ---------------------------------------------------------------- CBOR encoder
def _head(major: int, value: int) -> bytes:
    if value < 24:
        return bytes([(major << 5) | value])
    for minor, fmt in ((24, ">B"), (25, ">H"), (26, ">I"), (27, ">Q")):
        if value < 1 << (8 * struct.calcsize(fmt)):
            return bytes([(major << 5) | minor]) + struct.pack(fmt, value)
    raise ValueError("integer too large for CBOR")


def cbor_encode(obj: Any) -> bytes:
    if obj is None:
        return b"\xf6"
    if obj is True:
        return b"\xf5"
    if obj is False:
        return b"\xf4"
    if isinstance(obj, _Timestamp):
        return b"\xc1" + b"\xfb" + struct.pack(">d", obj.epoch)  # tag 1 + float64
    if isinstance(obj, int):
        return _head(0, obj) if obj >= 0 else _head(1, -1 - obj)
    if isinstance(obj, float):
        return b"\xfb" + struct.pack(">d", obj)
    if isinstance(obj, str):
        raw = obj.encode()
        return _head(3, len(raw)) + raw
    if isinstance(obj, (bytes, bytearray)):
        return _head(2, len(obj)) + bytes(obj)
    if isinstance(obj, list):
        return _head(4, len(obj)) + b"".join(cbor_encode(i) for i in obj)
    if isinstance(obj, dict):
        return _head(5, len(obj)) + b"".join(cbor_encode(k) + cbor_encode(v) for k, v in obj.items())
    raise TypeError(f"cannot CBOR-encode {type(obj)!r}")


# ---------------------------------------------------------------- CBOR decoder
class _Decoder:
    BREAK = object()

    def __init__(self, data: bytes) -> None:
        self.data, self.pos = data, 0

    def _take(self, n: int) -> bytes:
        chunk = self.data[self.pos : self.pos + n]
        if len(chunk) != n:
            raise ValueError("truncated CBOR")
        self.pos += n
        return chunk

    def _arg(self, minor: int) -> int | None:
        if minor < 24:
            return minor
        if minor in (24, 25, 26, 27):
            size = 1 << (minor - 24)
            return int.from_bytes(self._take(size), "big")
        if minor == 31:
            return None  # indefinite length
        raise ValueError(f"bad CBOR additional info {minor}")

    def decode(self) -> Any:
        initial = self._take(1)[0]
        major, minor = initial >> 5, initial & 0x1F
        if major == 7:
            if minor == 20:
                return False
            if minor == 21:
                return True
            if minor in (22, 23):
                return None
            if minor == 25:
                return struct.unpack(">e", self._take(2))[0]
            if minor == 26:
                return struct.unpack(">f", self._take(4))[0]
            if minor == 27:
                return struct.unpack(">d", self._take(8))[0]
            if minor == 31:
                return self.BREAK
            raise ValueError(f"unsupported simple value {minor}")
        arg = self._arg(minor)
        if major == 0:
            return arg
        if major == 1:
            return -1 - arg
        if major in (2, 3):
            if arg is None:
                parts = []
                while (item := self.decode()) is not self.BREAK:
                    parts.append(item)
                return (b"" if major == 2 else "").join(parts)
            raw = self._take(arg)
            return raw if major == 2 else raw.decode()
        if major == 4:
            if arg is None:
                items = []
                while (item := self.decode()) is not self.BREAK:
                    items.append(item)
                return items
            return [self.decode() for _ in range(arg)]
        if major == 5:
            result = {}
            if arg is None:
                while (key := self.decode()) is not self.BREAK:
                    result[key] = self.decode()
                return result
            for _ in range(arg):
                key = self.decode()
                result[key] = self.decode()
            return result
        if major == 6:
            value = self.decode()
            return value  # tag 1 (epoch timestamp) -> epoch number, as awsJson expects
        raise ValueError(f"unsupported CBOR major type {major}")


def cbor_decode(data: bytes) -> Any:
    return _Decoder(data).decode() if data else {}


def _jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        import base64

        return base64.b64encode(value).decode()
    if isinstance(value, list):
        return [_jsonable(v) for v in value]
    if isinstance(value, dict):
        return {k: _jsonable(v) for k, v in value.items()}
    return value


class _Timestamp:
    def __init__(self, epoch: float) -> None:
        self.epoch = epoch


def _to_epoch(value: Any) -> float:
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).replace("Z", "+00:00")
    parsed = dt.datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def shape_coerce(value: Any, shape: Any) -> Any:
    """Walk the botocore output shape converting JSON values to wire types."""
    if value is None or shape is None:
        return value
    kind = shape.type_name
    if kind == "structure" and isinstance(value, dict):
        return {k: shape_coerce(v, shape.members.get(k)) for k, v in value.items()}
    if kind == "list" and isinstance(value, list):
        return [shape_coerce(v, shape.member) for v in value]
    if kind == "map" and isinstance(value, dict):
        return {k: shape_coerce(v, shape.value) for k, v in value.items()}
    if kind == "timestamp":
        return _Timestamp(_to_epoch(value))
    if kind in ("double", "float") and isinstance(value, (int, float)):
        return float(value)
    if kind in ("integer", "long") and isinstance(value, (int, float)):
        return int(value)
    return value


def _output_shape(service: str, operation: str) -> Any:
    model = _MODELS.get(service)
    if model is None:
        for candidate in (service, service.lower(), "cloudwatch" if service == "GraniteServiceVersion20100801" else service):
            try:
                model = _SESSION.get_service_model(candidate)
                break
            except Exception:  # noqa: BLE001 - try the next candidate name
                continue
        _MODELS[service] = model
    if model is None:
        return None
    try:
        return model.operation_model(operation).output_shape
    except Exception:  # noqa: BLE001
        return None


# ------------------------------------------------------------------- proxy
class Handler(BaseHTTPRequestHandler):
    upstream_port = 0
    protocol_version = "HTTP/1.1"

    def log_message(self, *_: Any) -> None:  # keep output quiet
        return

    def _proxy(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        is_cbor = self.headers.get("Smithy-Protocol", "").lower() == "rpc-v2-cbor"
        headers = {k: v for k, v in self.headers.items() if k.lower() not in ("connection",)}
        path = self.path
        parts = self.path.split("/")
        service, operation = (parts[2], parts[4]) if is_cbor and len(parts) >= 5 else ("", "")
        if is_cbor:
            body = json.dumps(_jsonable(cbor_decode(body))).encode()
            for drop in ("Content-Type", "Smithy-Protocol", "Accept", "Content-Length", "Accept-Encoding"):
                headers.pop(drop, None)
            headers.update({
                "Content-Type": "application/x-amz-json-1.0",
                "X-Amz-Target": f"{service}.{operation}",
                "Content-Length": str(len(body)),
            })
            path = "/"
        conn = http.client.HTTPConnection("127.0.0.1", self.upstream_port, timeout=120)
        conn.request(self.command, path, body=body, headers=headers)
        resp = conn.getresponse()
        data = resp.read()

        if os.environ.get("SHIM_DEBUG") and is_cbor:
            redacted = {k: (v.split(",")[0] if k.lower() == "authorization" else v) for k, v in self.headers.items()}
            print(self.command, self.path, resp.status, redacted, data[:300], file=sys.stderr, flush=True)
        content_type = resp.getheader("Content-Type", "")
        if is_cbor and "cbor" not in content_type:
            try:
                parsed = json.loads(data.decode() or "{}")
            except ValueError:
                parsed = {}
            if resp.status >= 400 and isinstance(parsed, dict):
                code = parsed.get("__type") or parsed.get("Code") or parsed.get("code") or "InternalFailure"
                parsed = {"__type": code, "message": parsed.get("message") or parsed.get("Message") or ""}
            else:
                parsed = shape_coerce(parsed, _output_shape(service, operation))
            data = cbor_encode(parsed)
            content_type = "application/cbor"

        self.send_response(resp.status)
        for key, value in resp.getheaders():
            if key.lower() not in HOP_BY_HOP:
                self.send_header(key, value)
        if is_cbor:
            self.send_header("Smithy-Protocol", "rpc-v2-cbor")
        if content_type:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)
        conn.close()

    do_GET = do_POST = do_PUT = do_DELETE = do_HEAD = do_PATCH = _proxy


def main() -> None:
    listen, upstream = int(sys.argv[1]), int(sys.argv[2])
    Handler.upstream_port = upstream
    server = ThreadingHTTPServer(("127.0.0.1", listen), Handler)
    server.daemon_threads = True
    server.serve_forever()


if __name__ == "__main__":
    main()
