"""Policy Administration Point: the policy lifecycle.

    PAP MANAGES POLICIES.  PDP CONSUMES THEM.

No evaluation logic lives here, and no lifecycle logic lives in the PDP.

Where the truth lives, and why it is split three ways:

  policies/*.rego        the RULES. Version-controlled, reviewable, and the
                         only place an allow/deny is expressed.
  policies/data/*.json   the CONFIGURATION those rules read (Phase 5.5) --
                         approval thresholds and the like. Separate because it
                         changes for a different reason, is reviewed by
                         different people, and should not require editing a
                         rule to adjust a number. Pushed into OPA's own data
                         API, so Rego reads it as `data.` and nothing about the
                         decision moves into Python.
  policies/manifest.json the IDENTITY: policy id, version, owner, purpose,
                         scope, status. A .rego file cannot tell a reviewer who
                         owns it or whether it is live, so that is recorded
                         explicitly rather than left implicit.
  policies table         what the running system actually LOADED, and when,
                         with a content hash so drift between disk and engine
                         is detectable.

ACTIVATION IS REAL. Activating pushes the module into OPA; deactivating issues
DELETE /v1/policies/{id}, so the rules genuinely leave the engine rather than
being flagged inactive while still deciding.

CONFIGURATION IS RECONCILED TOO. OPA holds data in memory exactly as it holds
policy, so an OPA restart loses the thresholds as surely as it loses the rules.
The rules then fail closed -- which is safe, and is an outage nobody would
diagnose quickly if the reconciler only checked modules. So it checks both.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.audit.service import AuditService
from app.authorization.opa import OPAClient, OPAPolicyError, OPAUnavailableError
from app.core.config import Settings, get_settings
from app.core.errors import NotFoundError
from app.core.logging import get_logger
from app.db.models.authorization import PolicyRecord, PolicyStatus
from app.monitoring.events import Event, EventType

log = get_logger("authz.pap")

MANIFEST_NAME = "manifest.json"


class PolicyLoadError(RuntimeError):
    """A declared policy could not be loaded. Never silently ignored."""


@dataclass(frozen=True)
class DataDefinition:
    """One policy-configuration document as declared in the manifest.

    NOT a policy. It contains no rule and expresses no allow or deny -- it is
    the set of numbers a rule reads. Kept in the manifest anyway so it has the
    same identity a policy does: an owner, a version, a purpose, and a recorded
    statement of what happens when it is missing.
    """

    data_id: str
    version: str
    path: str
    source_path: str
    document: Any
    description: str | None = None
    purpose: str | None = None
    owner: str | None = None
    status: str = "ACTIVE"
    fails_closed: str | None = None

    @property
    def sha256(self) -> str:
        return hashlib.sha256(
            json.dumps(self.document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_id": self.data_id,
            "version": self.version,
            "path": self.path,
            "source_path": self.source_path,
            "description": self.description,
            "purpose": self.purpose,
            "owner": self.owner,
            "status": self.status,
            "fails_closed": self.fails_closed,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class PolicyDefinition:
    """One policy as declared in the manifest, with its Rego source."""

    policy_id: str
    version: str
    module_id: str
    source_path: str
    source: str
    description: str | None = None
    purpose: str | None = None
    scope: str | None = None
    owner: str | None = None
    status: str = "ACTIVE"

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.source.encode("utf-8")).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "version": self.version,
            "module_id": self.module_id,
            "source_path": self.source_path,
            "description": self.description,
            "purpose": self.purpose,
            "scope": self.scope,
            "owner": self.owner,
            "status": self.status,
            "sha256": self.sha256,
        }


class PolicyAdministrationPoint:
    def __init__(
        self,
        session: AsyncSession,
        settings: Settings | None = None,
        opa: OPAClient | None = None,
    ) -> None:
        self.session = session
        self.settings = settings or get_settings()
        self.opa = opa or OPAClient(self.settings)
        self.audit = AuditService(session)

    # --- reading the policy repository ------------------------------------
    @property
    def policy_dir(self) -> Path:
        return self.settings.resolved_policy_dir

    def read_definitions(self) -> list[PolicyDefinition]:
        """Parse the manifest and read each declared Rego module from disk."""
        manifest_path = self.policy_dir / MANIFEST_NAME
        if not manifest_path.is_file():
            raise PolicyLoadError(
                f"No policy manifest at {manifest_path}. The PAP will not guess "
                f"which .rego files are policies or what versions they are."
            )
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            raise PolicyLoadError(f"Policy manifest is not valid JSON: {exc}") from exc

        definitions: list[PolicyDefinition] = []
        for entry in manifest.get("policies", []):
            source_path = self.policy_dir / entry["source"]
            if not source_path.is_file():
                raise PolicyLoadError(
                    f"Policy {entry['policy_id']!r} declares source {entry['source']!r}, "
                    f"which does not exist at {source_path}"
                )
            definitions.append(
                PolicyDefinition(
                    policy_id=entry["policy_id"],
                    version=entry["version"],
                    module_id=entry["module_id"],
                    source_path=entry["source"],
                    source=source_path.read_text(),
                    description=entry.get("description"),
                    purpose=entry.get("purpose"),
                    scope=entry.get("scope"),
                    owner=entry.get("owner"),
                    status=entry.get("status", "ACTIVE"),
                )
            )
        return definitions

    def read_data_definitions(self) -> list[DataDefinition]:
        """Parse the manifest's `data` section and read each document."""
        manifest_path = self.policy_dir / MANIFEST_NAME
        if not manifest_path.is_file():
            raise PolicyLoadError(
                f"No policy manifest at {manifest_path}. The PAP will not guess "
                f"which JSON files are policy configuration."
            )
        try:
            manifest = json.loads(manifest_path.read_text())
        except json.JSONDecodeError as exc:
            raise PolicyLoadError(f"Policy manifest is not valid JSON: {exc}") from exc

        definitions: list[DataDefinition] = []
        for entry in manifest.get("data", []):
            source_path = self.policy_dir / entry["source"]
            if not source_path.is_file():
                raise PolicyLoadError(
                    f"Policy data {entry['data_id']!r} declares source "
                    f"{entry['source']!r}, which does not exist at {source_path}"
                )
            try:
                document = json.loads(source_path.read_text())
            except json.JSONDecodeError as exc:
                raise PolicyLoadError(
                    f"Policy data {entry['data_id']!r} at {source_path} is not "
                    f"valid JSON: {exc}"
                ) from exc
            definitions.append(
                DataDefinition(
                    data_id=entry["data_id"],
                    version=entry["version"],
                    path=entry["path"],
                    source_path=entry["source"],
                    document=document,
                    description=entry.get("description"),
                    purpose=entry.get("purpose"),
                    owner=entry.get("owner"),
                    status=entry.get("status", "ACTIVE"),
                    fails_closed=entry.get("fails_closed"),
                )
            )
        return definitions

    async def load_data(self, *, record: bool = True) -> dict[str, Any]:
        """Push every ACTIVE configuration document into OPA.

        Raises if OPA refuses one. A rule whose configuration failed to load
        denies -- correctly -- and an unnoticed failure here would look like a
        policy bug rather than a missing document.
        """
        loaded: list[str] = []
        skipped: list[str] = []
        for definition in self.read_data_definitions():
            if definition.status != "ACTIVE":
                skipped.append(definition.data_id)
                continue
            await self.opa.put_data(definition.path, definition.document)
            loaded.append(definition.data_id)
            if record:
                await self.audit.record(
                    Event(
                        EventType.POLICY_DATA_LOADED,
                        resource=definition.data_id,
                        action="LOAD_POLICY_DATA",
                        decision="LOADED",
                        metadata={
                            "data_id": definition.data_id,
                            "version": definition.version,
                            "path": definition.path,
                            "sha256": definition.sha256,
                            "owner": definition.owner,
                        },
                    )
                )
        log.info("policy_data_loaded", loaded=loaded, skipped=skipped,
                 engine=self.opa.base_url)
        return {"loaded": loaded, "skipped": skipped}

    # --- loading into OPA --------------------------------------------------
    async def load_all(self, *, record: bool = True) -> dict[str, Any]:
        """Push every ACTIVE policy into OPA and record what was loaded.

        Raises if OPA rejects a module: a policy set that does not compile must
        not be treated as loaded, because the PDP would then be denying
        everything for a reason nobody noticed.
        """
        definitions = self.read_definitions()
        loaded: list[str] = []
        skipped: list[str] = []

        for definition in definitions:
            if definition.status != "ACTIVE":
                skipped.append(definition.policy_id)
                await self._upsert(definition, PolicyStatus.INACTIVE, loaded_at=None)
                continue
            await self.opa.put_policy(definition.module_id, definition.source)
            await self._upsert(definition, PolicyStatus.ACTIVE,
                               loaded_at=datetime.now(timezone.utc))
            loaded.append(definition.policy_id)
            if record:
                await self.audit.record(
                    Event(
                        EventType.POLICY_LOADED,
                        resource=definition.policy_id,
                        action="LOAD_POLICY",
                        decision="LOADED",
                        metadata={
                            "policy_id": definition.policy_id,
                            "version": definition.version,
                            "module_id": definition.module_id,
                            "sha256": definition.sha256,
                            "owner": definition.owner,
                        },
                    )
                )
        # Configuration LAST, and unconditionally: a rule pushed without the
        # numbers it reads denies until they arrive, so the window between the
        # two should be as short as possible and must never be skipped.
        data_result = await self.load_data(record=record)

        log.info("policies_loaded", loaded=loaded, skipped=skipped,
                 data=data_result["loaded"], engine=self.opa.base_url)
        return {"loaded": loaded, "skipped": skipped, "engine": self.opa.base_url,
                "data": data_result}

    async def _upsert(
        self, definition: PolicyDefinition, status: PolicyStatus,
        loaded_at: datetime | None,
    ) -> PolicyRecord:
        record = await self.get(definition.policy_id)
        if record is None:
            record = PolicyRecord(policy_id=definition.policy_id)
            self.session.add(record)
        record.version = definition.version
        record.module_id = definition.module_id
        record.description = definition.description
        record.purpose = definition.purpose
        record.scope = definition.scope
        record.owner = definition.owner
        record.status = status
        record.source_path = definition.source_path
        record.source_sha256 = definition.sha256
        record.loaded_at = loaded_at
        await self.session.flush()
        return record

    # --- lifecycle ---------------------------------------------------------
    async def get(self, policy_id: str) -> PolicyRecord | None:
        result = await self.session.execute(
            select(PolicyRecord).where(PolicyRecord.policy_id == policy_id)
        )
        return result.scalar_one_or_none()

    async def list_policies(self) -> list[PolicyRecord]:
        result = await self.session.execute(
            select(PolicyRecord).order_by(PolicyRecord.policy_id)
        )
        return list(result.scalars().all())

    async def activate(self, policy_id: str) -> PolicyRecord:
        definition = self._definition(policy_id)
        await self.opa.put_policy(definition.module_id, definition.source)
        record = await self._upsert(definition, PolicyStatus.ACTIVE,
                                    datetime.now(timezone.utc))
        await self.audit.record(
            Event(
                EventType.POLICY_ACTIVATED,
                resource=policy_id, action="ACTIVATE_POLICY", decision="ACTIVE",
                metadata={"policy_id": policy_id, "version": definition.version,
                          "module_id": definition.module_id},
            )
        )
        log.info("policy_activated", policy_id=policy_id, version=definition.version)
        return record

    async def deactivate(self, policy_id: str) -> PolicyRecord:
        """Remove a policy from the engine.

        The module is DELETEd from OPA, so its rules stop being evaluated. This
        is why deactivation is meaningful rather than cosmetic.
        """
        record = await self.get(policy_id)
        if record is None:
            raise NotFoundError(f"Unknown policy {policy_id}")
        await self.opa.delete_policy(record.module_id)
        record.status = PolicyStatus.INACTIVE
        record.loaded_at = None
        await self.session.flush()
        await self.audit.record(
            Event(
                EventType.POLICY_DEACTIVATED,
                resource=policy_id, action="DEACTIVATE_POLICY", decision="INACTIVE",
                metadata={"policy_id": policy_id, "module_id": record.module_id},
            )
        )
        log.warning("policy_deactivated", policy_id=policy_id, module_id=record.module_id)
        return record

    def _definition(self, policy_id: str) -> PolicyDefinition:
        for definition in self.read_definitions():
            if definition.policy_id == policy_id:
                return definition
        raise NotFoundError(f"Unknown policy {policy_id}")

    async def reconcile(self) -> dict[str, Any]:
        """Reload the policy set if OPA is missing any ACTIVE module.

        WHY THIS EXISTS: OPA holds policy in memory. If the OPA process restarts
        after the API has started, it comes back with an EMPTY policy set --
        and because the combining algorithm is default-deny, the system then
        denies everything until policy is pushed again. That is safe (it fails
        closed) but it does not recover on its own, so an OPA restart would
        otherwise be an outage that needs manual intervention.

        Cheap by design: a single GET, and a reload only when something is
        genuinely absent.
        """
        try:
            in_engine = set(await self.opa.list_policies())
        except OPAUnavailableError as exc:
            return {"reconciled": False, "reason": f"OPA unreachable: {exc}"}

        expected = {
            d.module_id for d in self.read_definitions() if d.status == "ACTIVE"
        }
        missing = expected - in_engine

        # Configuration is held in memory by OPA exactly as policy is, so an
        # engine restart loses the thresholds too. The rules that read them
        # fail closed, which is safe and invisible -- so it is checked here
        # rather than left to be discovered as "loans are all being denied".
        missing_data: list[str] = []
        try:
            for definition in self.read_data_definitions():
                if definition.status != "ACTIVE":
                    continue
                if await self.opa.get_data(definition.path) is None:
                    missing_data.append(definition.data_id)
        except (OPAUnavailableError, PolicyLoadError) as exc:
            return {"reconciled": False, "reason": f"policy data unreadable: {exc}"}

        if not missing and not missing_data:
            return {"reconciled": False, "reason": "policy set intact",
                    "modules": len(in_engine)}

        log.warning("policy_set_incomplete", missing=sorted(missing),
                    missing_data=sorted(missing_data),
                    detail="OPA is missing active modules or configuration; reloading")
        result = await self.load_all()
        return {"reconciled": True, "restored": sorted(missing),
                "restored_data": sorted(missing_data), **result}

    # --- drift -------------------------------------------------------------
    async def status_report(self) -> dict[str, Any]:
        """What the manifest declares vs what OPA is actually running.

        Answers the question an operator actually has during an incident:
        "is the policy I am reading the policy that decided?"
        """
        try:
            in_engine = set(await self.opa.list_policies())
            engine_reachable = True
        except OPAUnavailableError as exc:
            in_engine, engine_reachable = set(), False
            log.error("opa_unreachable_for_status", error=str(exc))

        try:
            definitions = {d.policy_id: d for d in self.read_definitions()}
            manifest_ok, manifest_error = True, None
        except PolicyLoadError as exc:
            definitions, manifest_ok, manifest_error = {}, False, str(exc)

        rows = []
        for record in await self.list_policies():
            definition = definitions.get(record.policy_id)
            rows.append({
                "policy_id": record.policy_id,
                "version": record.version,
                "status": record.status.value,
                "owner": record.owner,
                "scope": record.scope,
                "module_id": record.module_id,
                "in_engine": record.module_id in in_engine,
                "source_drift": (
                    None if definition is None
                    else definition.sha256 != record.source_sha256
                ),
                "loaded_at": record.loaded_at.isoformat() if record.loaded_at else None,
            })
        data_rows = []
        if manifest_ok:
            for definition in self.read_data_definitions():
                try:
                    live = (await self.opa.get_data(definition.path)
                            if engine_reachable else None)
                except OPAUnavailableError:
                    live = None
                data_rows.append({
                    **definition.to_dict(),
                    # The question an operator actually has: are the numbers
                    # that are deciding right now the numbers in the repository?
                    "in_engine": live is not None,
                    "source_drift": (
                        None if live is None
                        else json.dumps(live, sort_keys=True)
                        != json.dumps(definition.document, sort_keys=True)
                    ),
                })

        return {
            "engine": {"url": self.opa.base_url, "reachable": engine_reachable,
                       "modules": sorted(in_engine)},
            "manifest": {"ok": manifest_ok, "error": manifest_error},
            "policies": rows,
            "data": data_rows,
        }
