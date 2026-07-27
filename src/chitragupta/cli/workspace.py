"""The CLI's local workspace: where dev keys, sealed manifests, grants, the
durable grant store, and the audit journal live between separate CLI
invocations (each ``chitragupta`` command is its own process).

Default location is ``.chitragupta`` under the current directory, overridable
with ``--workspace`` or the ``CHITRAGUPTA_HOME`` environment variable.
"""

from __future__ import annotations

import dataclasses
import json
import os
from datetime import datetime
from pathlib import Path

from chitragupta.adapters.base import CommitResult, CompensationResult, OutcomeProof
from chitragupta.audit.journal import AuditJournal
from chitragupta.audit.sqlite_backend import SQLiteAuditBackend
from chitragupta.crypto.keyring import Keyring
from chitragupta.crypto.keys import (
    SigningKey,
    VerificationKey,
    generate_signing_key,
    load_signing_key_from_file,
    save_signing_key_to_file,
)
from chitragupta.domain.manifest import EffectManifest
from chitragupta.domain.seal import SealedManifest
from chitragupta.engine.context import EngineContext
from chitragupta.engine.core import ChitraguptaEngine
from chitragupta.errors import KeyLoadError
from chitragupta.grants.model import ExecutionGrant
from chitragupta.state_machine.states import LifecycleState
from chitragupta.stores.sqlite import SQLiteGrantStore

DEFAULT_WORKSPACE_ENV = "CHITRAGUPTA_HOME"
DEFAULT_WORKSPACE_DIRNAME = ".chitragupta"


def default_workspace_path() -> Path:
    env = os.environ.get(DEFAULT_WORKSPACE_ENV)
    if env:
        return Path(env)
    return Path.cwd() / DEFAULT_WORKSPACE_DIRNAME


class Workspace:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.keys_dir = self.root / "keys"
        self.manifests_dir = self.root / "manifests"
        self.grants_dir = self.root / "grants"

    def ensure_initialized(self) -> None:
        for d in (self.root, self.keys_dir, self.manifests_dir, self.grants_dir):
            d.mkdir(parents=True, exist_ok=True)

    def is_initialized(self) -> bool:
        return self.root.exists() and self.keys_dir.exists()

    # --- keys ---------------------------------------------------------------

    def _pubkey_path(self, key_id: str) -> Path:
        return self.keys_dir / f"{key_id}.pub.json"

    def _privkey_path(self, key_id: str) -> Path:
        return self.keys_dir / f"{key_id}.priv"

    def has_key(self, key_id: str) -> bool:
        return self._pubkey_path(key_id).exists()

    def generate_key(self, key_id: str) -> SigningKey:
        key = generate_signing_key(key_id)
        save_signing_key_to_file(key, self._privkey_path(key_id))
        self._pubkey_path(key_id).write_text(
            json.dumps(
                {
                    "key_id": key_id,
                    "algorithm": key.algorithm,
                    "public_b64": key.verification_key().public_bytes_b64(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return key

    def load_signing_key(self, key_id: str) -> SigningKey:
        path = self._privkey_path(key_id)
        if not path.exists():
            raise KeyLoadError(f"no private key found for key_id={key_id!r} in {self.keys_dir}")
        return load_signing_key_from_file(path, key_id)

    def list_key_ids(self) -> list[str]:
        return sorted(p.stem.removesuffix(".pub") for p in self.keys_dir.glob("*.pub.json"))

    def load_keyring(self) -> Keyring:
        keys = []
        for path in sorted(self.keys_dir.glob("*.pub.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            keys.append(
                VerificationKey.from_public_b64(
                    data["key_id"], data["public_b64"], data.get("algorithm", "ed25519")
                )
            )
        return Keyring(keys)

    # --- manifests / seals ----------------------------------------------------

    def save_sealed_manifest(self, sealed: SealedManifest) -> Path:
        path = self.manifests_dir / f"{sealed.manifest.manifest_id}.json"
        path.write_text(sealed.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load_sealed_manifest(self, manifest_id: str) -> SealedManifest:
        path = self.manifests_dir / f"{manifest_id}.json"
        return SealedManifest.model_validate_json(path.read_text(encoding="utf-8"))

    def save_unsealed_manifest(self, manifest: EffectManifest) -> Path:
        path = self.manifests_dir / f"{manifest.manifest_id}.unsealed.json"
        path.write_text(manifest.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load_unsealed_manifest(self, manifest_id: str) -> EffectManifest:
        path = self.manifests_dir / f"{manifest_id}.unsealed.json"
        return EffectManifest.model_validate_json(path.read_text(encoding="utf-8"))

    # --- grants -------------------------------------------------------------

    def save_grant(self, grant: ExecutionGrant) -> Path:
        path = self.grants_dir / f"{grant.grant_id}.json"
        path.write_text(grant.model_dump_json(indent=2), encoding="utf-8")
        return path

    def load_grant(self, grant_id: str) -> ExecutionGrant:
        path = self.grants_dir / f"{grant_id}.json"
        return ExecutionGrant.model_validate_json(path.read_text(encoding="utf-8"))

    # --- commit results -------------------------------------------------------

    def save_commit_result(self, manifest_id: str, result: CommitResult) -> Path:
        path = self.manifests_dir / f"{manifest_id}.commit.json"
        path.write_text(json.dumps(dataclasses.asdict(result), indent=2), encoding="utf-8")
        return path

    def load_commit_result(self, manifest_id: str) -> CommitResult | None:
        path = self.manifests_dir / f"{manifest_id}.commit.json"
        if not path.exists():
            return None
        return CommitResult(**json.loads(path.read_text(encoding="utf-8")))

    def save_outcome_proof(self, manifest_id: str, proof: OutcomeProof) -> Path:
        path = self.manifests_dir / f"{manifest_id}.proof.json"
        path.write_text(
            json.dumps(dataclasses.asdict(proof), default=str, indent=2), encoding="utf-8"
        )
        return path

    def load_outcome_proof(self, manifest_id: str) -> OutcomeProof | None:
        path = self.manifests_dir / f"{manifest_id}.proof.json"
        if not path.exists():
            return None
        data = json.loads(path.read_text(encoding="utf-8"))
        data["observed_at"] = datetime.fromisoformat(data["observed_at"])
        return OutcomeProof(**data)

    def save_compensation_result(self, manifest_id: str, result: CompensationResult) -> Path:
        path = self.manifests_dir / f"{manifest_id}.compensation.json"
        path.write_text(json.dumps(dataclasses.asdict(result), indent=2), encoding="utf-8")
        return path

    def load_compensation_result(self, manifest_id: str) -> CompensationResult | None:
        path = self.manifests_dir / f"{manifest_id}.compensation.json"
        if not path.exists():
            return None
        return CompensationResult(**json.loads(path.read_text(encoding="utf-8")))

    # --- durable stores -------------------------------------------------------

    def open_grant_store(self) -> SQLiteGrantStore:
        return SQLiteGrantStore(self.root / "grants.db")

    def open_audit(self) -> AuditJournal:
        return AuditJournal(backend=SQLiteAuditBackend(self.root / "audit.db"))

    def build_engine(self) -> ChitraguptaEngine:
        ctx = EngineContext(
            keyring=self.load_keyring(),
            grant_store=self.open_grant_store(),
            audit=self.open_audit(),
        )
        return ChitraguptaEngine(ctx)

    def reconstruct_lifecycle_state(self, engine: ChitraguptaEngine, manifest_id: str) -> None:
        """Seed ``engine``'s in-memory lifecycle record for ``manifest_id``
        from the durable audit journal, so a fresh per-invocation engine
        continues from wherever a previous CLI invocation left off."""
        events = [e for e in engine.context.audit.events_for_manifest(manifest_id) if e.to_state]
        if not events:
            return
        last = events[-1]
        assert last.to_state is not None
        engine.seed_lifecycle_state(manifest_id, LifecycleState(last.to_state))


__all__ = ["DEFAULT_WORKSPACE_ENV", "Workspace", "default_workspace_path"]
