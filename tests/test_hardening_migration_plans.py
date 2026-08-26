import hashlib
import json
from pathlib import Path


def test_hardening_migration_plan_digests_are_canonical() -> None:
    for path in sorted(Path("governance/migration-plans").glob("20260824_*.json")):
        payload = json.loads(path.read_text(encoding="utf-8"))
        expected = payload.pop("plan_sha256")
        canonical = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode()
        assert hashlib.sha256(canonical).hexdigest() == expected
