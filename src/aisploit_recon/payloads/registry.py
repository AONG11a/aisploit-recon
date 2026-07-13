"""Payload registry.

Loads YAML payload definitions from a directory, validates them against the
``Payload`` schema, enforces unique IDs, and provides filtered views by
category / tag. Validation errors are fatal — a malformed payload file should
stop a run, not silently ship a broken test.
"""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import ValidationError

from aisploit_recon.payloads.models import DetectionStrategy, Payload, PayloadCategory
from aisploit_recon.utils.logging import get_logger

log = get_logger(__name__)


class PayloadRegistryError(Exception):
    pass


class PayloadRegistry:
    def __init__(self) -> None:
        self._payloads: dict[str, Payload] = {}

    @classmethod
    def from_directory(cls, directory: Path) -> PayloadRegistry:
        registry = cls()
        if not directory.exists():
            raise PayloadRegistryError(f"Payload directory not found: {directory}")

        yaml_files = sorted(directory.glob("*.yaml")) + sorted(directory.glob("*.yml"))
        if not yaml_files:
            raise PayloadRegistryError(f"No YAML payload files in {directory}")

        for path in yaml_files:
            registry._load_file(path)

        log.info("registry.loaded", count=len(registry._payloads), files=len(yaml_files))
        return registry

    def _load_file(self, path: Path) -> None:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise PayloadRegistryError(f"YAML parse error in {path}: {exc}") from exc

        if not isinstance(raw, list):
            raise PayloadRegistryError(f"{path} must contain a list of payloads")

        for i, item in enumerate(raw):
            try:
                payload = Payload.model_validate(item)
            except ValidationError as exc:
                raise PayloadRegistryError(
                    f"Invalid payload #{i} in {path.name}: {exc}"
                ) from exc
            if payload.id in self._payloads:
                raise PayloadRegistryError(
                    f"Duplicate payload id {payload.id!r} (in {path.name})"
                )
            # Detection strategy requires a canary but template has no
            # placeholder — this would silently produce ERROR verdicts at scan
            # time. Fail at load (philosophy: broken payload stops the run).
            if payload.detection is DetectionStrategy.CANARY and not payload.requires_canary:
                raise PayloadRegistryError(
                    f"Payload {payload.id!r} uses canary detection but its "
                    f"template has no {{canary}} placeholder (in {path.name})"
                )
            self._payloads[payload.id] = payload

    def all(self) -> list[Payload]:
        return list(self._payloads.values())

    def enabled(self) -> list[Payload]:
        return [p for p in self._payloads.values() if p.enabled]

    def by_category(self, category: PayloadCategory) -> list[Payload]:
        return [p for p in self._payloads.values() if p.category is category]

    def by_tag(self, tag: str) -> list[Payload]:
        return [p for p in self._payloads.values() if tag in p.tags]

    def get(self, payload_id: str) -> Payload:
        try:
            return self._payloads[payload_id]
        except KeyError as exc:
            raise PayloadRegistryError(f"Unknown payload id: {payload_id!r}") from exc
