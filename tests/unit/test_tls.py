import os
import stat

from cryptography import x509

from sci_app.tls import ensure_self_signed


def test_generates_key_with_private_permissions(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    ensure_self_signed(str(cert), str(key))
    assert stat.S_IMODE(os.stat(key).st_mode) == 0o600
    parsed = x509.load_pem_x509_certificate(cert.read_bytes())
    assert parsed.subject.rfc4514_string() == "CN=sci-app.internal"


def test_does_not_overwrite_existing(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    ensure_self_signed(str(cert), str(key))
    before = cert.read_bytes()
    ensure_self_signed(str(cert), str(key))
    assert cert.read_bytes() == before
