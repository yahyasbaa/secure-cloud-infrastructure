"""Normalised view of every Terraform file in the repository.

python-hcl2 keeps string literals quoted ('"Allow"') and expressions wrapped in
'${...}'. This module strips literal quotes and indexes resources and data
sources per module so tests can reason about the configuration statically.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import hcl2

ROOT = Path(__file__).resolve().parents[3]
TF_ROOT = ROOT / "terraform"

EXPR = re.compile(r"^\$\{(.*)\}$", re.S)


def unquote(value: Any) -> Any:
    """'"abc"' -> 'abc'; recursively for lists/dicts; drop '__is_block__'."""
    if isinstance(value, str):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            return value[1:-1]
        return value
    if isinstance(value, list):
        return [unquote(v) for v in value]
    if isinstance(value, dict):
        return {unquote(k): unquote(v) for k, v in value.items() if k != "__is_block__"}
    return value


def is_expr(value: Any) -> bool:
    return isinstance(value, str) and bool(EXPR.match(value))


def expr_body(value: str) -> str:
    m = EXPR.match(value)
    return m.group(1).strip() if m else value


@dataclass
class Block:
    kind: str  # resource | data
    type: str
    name: str
    module_dir: Path
    file: Path
    body: dict[str, Any]

    @property
    def address(self) -> str:
        rel = self.module_dir.relative_to(TF_ROOT)
        prefix = "" if str(rel) == "." else f"{rel}:"
        kind = "data." if self.kind == "data" else ""
        return f"{prefix}{kind}{self.type}.{self.name}"


@dataclass
class Config:
    blocks: list[Block] = field(default_factory=list)
    locals: dict[Path, dict[str, Any]] = field(default_factory=dict)
    files: list[Path] = field(default_factory=list)

    def resources(self, rtype: str) -> list[Block]:
        return [b for b in self.blocks if b.kind == "resource" and b.type == rtype]

    def data(self, dtype: str) -> list[Block]:
        return [b for b in self.blocks if b.kind == "data" and b.type == dtype]

    def find(self, kind: str, rtype: str, name: str, module_dir: Path) -> Block | None:
        for b in self.blocks:
            if b.kind == kind and b.type == rtype and b.name == name and b.module_dir == module_dir:
                return b
        return None


def terraform_files() -> list[Path]:
    return sorted(
        p
        for p in TF_ROOT.rglob("*.tf")
        if ".terraform" not in p.parts and "tests" not in p.relative_to(TF_ROOT).parts
    )


@lru_cache(maxsize=1)
def load() -> Config:
    cfg = Config()
    for path in terraform_files():
        with path.open() as fh:
            parsed = hcl2.load(fh)
        cfg.files.append(path)
        module_dir = path.parent
        for loc in parsed.get("locals", []):
            cfg.locals.setdefault(module_dir, {}).update(unquote(loc))
        for kind in ("resource", "data"):
            for entry in parsed.get(kind, []):
                for rtype, named in entry.items():
                    for name, body in named.items():
                        cfg.blocks.append(
                            Block(kind, unquote(rtype), unquote(name), module_dir, path, unquote(body))
                        )
    return cfg


def resolve_list(value: Any, block: Block, cfg: Config) -> list[str] | None:
    """Resolve an attribute that should be a list of strings.

    Supports literal lists, ``local.X`` (list) and ``each.value`` when the block
    iterates over a map of lists in a local. Returns None if unresolvable.
    """
    if isinstance(value, list):
        out: list[str] = []
        for v in value:
            if isinstance(v, str):
                out.append(v)
            else:
                return None
        return out
    if not is_expr(value):
        return None
    body = expr_body(value)
    local_vals = cfg.locals.get(block.module_dir, {})
    m = re.fullmatch(r"local\.(\w+)", body)
    if m and isinstance(local_vals.get(m.group(1)), list):
        return [str(v) for v in local_vals[m.group(1)]]
    if body == "each.value":
        fe = block.body.get("for_each")
        if is_expr(fe):
            m = re.fullmatch(r"local\.(\w+)", expr_body(fe))
            mapping = local_vals.get(m.group(1)) if m else None
            if isinstance(mapping, dict) and all(isinstance(v, list) for v in mapping.values()):
                return sorted({str(a) for v in mapping.values() for a in v})
    return None


def statements(block: Block) -> list[dict[str, Any]]:
    """Statements of an aws_iam_policy_document, including dynamic ones."""
    out = list(block.body.get("statement", []))
    for dyn in block.body.get("dynamic", []):
        for label, spec in dyn.items():
            if label == "statement":
                out.extend(spec.get("content", []))
    return out


def policy_consumers(cfg: Config) -> dict[str, list[tuple[Block, str]]]:
    """Map 'module_dir|doc_name' -> [(consuming block, attribute)]."""
    refs: dict[str, list[tuple[Block, str]]] = {}
    pattern = re.compile(r"data\.aws_iam_policy_document\.(\w+)(?:\[[^\]]+\])?\.json")
    for b in cfg.blocks:
        for attr, value in b.body.items():
            if isinstance(value, str):
                for m in pattern.finditer(value):
                    refs.setdefault(f"{b.module_dir}|{m.group(1)}", []).append((b, attr))
    return refs


def classify_policy_documents(cfg: Config) -> dict[str, list[Block]]:
    """Group policy documents by how they are used."""
    groups: dict[str, list[Block]] = {"identity": [], "trust": [], "resource": [], "unused": []}
    consumers = policy_consumers(cfg)
    for doc in cfg.data("aws_iam_policy_document"):
        users = consumers.get(f"{doc.module_dir}|{doc.name}", [])
        if not users:
            groups["unused"].append(doc)
            continue
        kinds = set()
        for consumer, attr in users:
            if attr == "assume_role_policy":
                kinds.add("trust")
            elif consumer.type in ("aws_iam_role_policy", "aws_iam_policy", "aws_iam_user_policy", "aws_iam_group_policy"):
                kinds.add("identity")
            else:
                kinds.add("resource")
        for k in kinds:
            groups[k].append(doc)
    return groups
