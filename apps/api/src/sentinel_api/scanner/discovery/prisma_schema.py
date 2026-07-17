"""Focused deterministic parser for supported Prisma schema syntax."""

import re
from dataclasses import dataclass

from sentinel_api.scanner.discovery.models import (
    OwnershipCandidate,
    OwnershipCandidateType,
    PrismaDataModel,
    PrismaField,
    PrismaGenerator,
    PrismaModel,
)
from sentinel_api.scanner.models import IndexResult

_BLOCK_START = re.compile(r"(?m)^\s*(datasource|generator|model|enum)\s+([A-Za-z_]\w*)\s*\{")
_ASSIGNMENT = re.compile(r"(?m)^\s*([A-Za-z_]\w*)\s*=\s*[\"']([^\"']+)[\"']")
_RELATION_FIELDS = re.compile(r"\bfields\s*:\s*\[([^\]]+)]")
_MODEL_FIELD_LIST = re.compile(r"@@(?:id|unique)\s*\(\s*\[([^\]]+)]")

_OWNERSHIP_PATTERNS: dict[str, tuple[OwnershipCandidateType, float]] = {
    "ownerid": ("direct_owner", 0.95),
    "createdby": ("direct_owner", 0.9),
    "createdbyid": ("direct_owner", 0.95),
    "authorid": ("direct_owner", 0.92),
    "userid": ("user_reference", 0.9),
    "memberid": ("member_reference", 0.85),
    "accountid": ("account_scope", 0.9),
    "organizationid": ("organization_scope", 0.92),
    "organisationid": ("organization_scope", 0.92),
    "tenantid": ("tenant_scope", 0.96),
    "workspaceid": ("workspace_scope", 0.92),
    "teamid": ("team_scope", 0.9),
}


@dataclass(frozen=True, slots=True)
class _Block:
    kind: str
    name: str
    body: str
    start_line: int


@dataclass(frozen=True, slots=True)
class _RawField:
    name: str
    type_name: str
    is_optional: bool
    is_list: bool
    attributes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _RawModel:
    name: str
    fields: tuple[_RawField, ...]
    model_attributes: tuple[str, ...]


class PrismaSchemaParser:
    """Parse the Prisma constructs used by the bundled controlled demo."""

    def parse(self, index: IndexResult) -> tuple[PrismaDataModel, list[str]]:
        """Return deterministic model metadata and partial-syntax warnings."""
        source_file = self._schema_path(index)
        if source_file is None:
            return PrismaDataModel(
                provider=None,
                generators=[],
                models=[],
                ownership_candidates=[],
            ), []
        content = index.contents.get(source_file)
        if content is None:
            return (
                PrismaDataModel(
                    provider=None,
                    generators=[],
                    models=[],
                    ownership_candidates=[],
                ),
                ["Prisma schema exists but was not available for static inspection"],
            )

        blocks, warnings = self._blocks(content, source_file)
        datasource_blocks = [block for block in blocks if block.kind == "datasource"]
        generator_blocks = [block for block in blocks if block.kind == "generator"]
        model_blocks = [block for block in blocks if block.kind == "model"]
        enum_names = {block.name for block in blocks if block.kind == "enum"}
        provider = (
            self._property(datasource_blocks[0].body, "provider")
            if datasource_blocks
            else None
        )
        generators = sorted(
            (
                PrismaGenerator(
                    name=block.name,
                    provider=self._property(block.body, "provider"),
                    output=self._property(block.body, "output"),
                )
                for block in generator_blocks
            ),
            key=lambda item: item.name,
        )

        raw_models = [self._raw_model(block, source_file, warnings) for block in model_blocks]
        model_names = {model.name for model in raw_models}
        models = [
            self._resolve_model(model, model_names, enum_names, source_file)
            for model in raw_models
        ]
        models.sort(key=lambda item: item.name)
        ownership = self._ownership_candidates(models)
        return PrismaDataModel(
            provider=provider,
            generators=generators,
            models=models,
            ownership_candidates=ownership,
        ), warnings

    @staticmethod
    def _schema_path(index: IndexResult) -> str | None:
        candidates = sorted(
            path for path in index.contents if path.endswith("schema.prisma")
        )
        return candidates[0] if candidates else None

    @staticmethod
    def _blocks(content: str, source_file: str) -> tuple[list[_Block], list[str]]:
        masked = _mask_prisma_comments(content)
        blocks: list[_Block] = []
        warnings: list[str] = []
        for match in _BLOCK_START.finditer(masked):
            opening = masked.find("{", match.start(), match.end())
            closing = _matching_brace(masked, opening)
            if closing is None:
                warnings.append(
                    f"Unclosed Prisma {match.group(1)} block at "
                    f"{source_file}:{_line(content, match.start())}"
                )
                continue
            blocks.append(
                _Block(
                    kind=match.group(1),
                    name=match.group(2),
                    body=content[opening + 1 : closing],
                    start_line=_line(content, match.start()),
                )
            )
        if "model " in content and not any(block.kind == "model" for block in blocks):
            warnings.append("Prisma model syntax was present but could not be parsed")
        return blocks, warnings

    @staticmethod
    def _raw_model(block: _Block, source_file: str, warnings: list[str]) -> _RawModel:
        fields: list[_RawField] = []
        model_attributes: list[str] = []
        for offset, original_line in enumerate(block.body.splitlines(), start=1):
            line = original_line.split("//", maxsplit=1)[0].strip()
            if not line:
                continue
            if line.startswith("@@"):
                model_attributes.append(line)
                continue
            tokens = line.split(maxsplit=2)
            if len(tokens) < 2 or tokens[0].startswith("@"):  # unsupported declaration
                warnings.append(
                    f"Unsupported Prisma model syntax at {source_file}:{block.start_line + offset}"
                )
                continue
            raw_type = tokens[1]
            is_list = raw_type.endswith("[]")
            without_list = raw_type[:-2] if is_list else raw_type
            is_optional = without_list.endswith("?")
            type_name = without_list[:-1] if is_optional else without_list
            attributes = tuple(_parse_attributes(tokens[2] if len(tokens) == 3 else ""))
            fields.append(
                _RawField(
                    name=tokens[0],
                    type_name=type_name,
                    is_optional=is_optional,
                    is_list=is_list,
                    attributes=attributes,
                )
            )
        return _RawModel(
            name=block.name,
            fields=tuple(fields),
            model_attributes=tuple(model_attributes),
        )

    @staticmethod
    def _resolve_model(
        model: _RawModel,
        model_names: set[str],
        enum_names: set[str],
        source_file: str,
    ) -> PrismaModel:
        relation_foreign_keys: dict[str, str] = {}
        for field in model.fields:
            if field.type_name not in model_names:
                continue
            relation_attribute = next(
                (attribute for attribute in field.attributes if attribute.startswith("@relation")),
                None,
            )
            if relation_attribute:
                match = _RELATION_FIELDS.search(relation_attribute)
                if match:
                    for foreign_key in _field_names(match.group(1)):
                        relation_foreign_keys[foreign_key] = field.type_name

        model_primary_keys: set[str] = set()
        model_unique_fields: set[str] = set()
        for attribute in model.model_attributes:
            match = _MODEL_FIELD_LIST.search(attribute)
            if match is None:
                continue
            names = set(_field_names(match.group(1)))
            if attribute.startswith("@@id"):
                model_primary_keys.update(names)
            elif attribute.startswith("@@unique"):
                model_unique_fields.update(names)

        resolved_fields: list[PrismaField] = []
        for field in model.fields:
            is_primary = "@id" in field.attributes or field.name in model_primary_keys
            is_unique = "@unique" in field.attributes or field.name in model_unique_fields
            default_attribute = next(
                (attribute for attribute in field.attributes if attribute.startswith("@default")),
                None,
            )
            is_relation = field.type_name in model_names
            relation_model = (
                field.type_name if is_relation else relation_foreign_keys.get(field.name)
            )
            resolved_fields.append(
                PrismaField(
                    name=field.name,
                    type=field.type_name,
                    is_optional=field.is_optional,
                    is_list=field.is_list,
                    is_primary_key=is_primary,
                    is_unique=is_unique,
                    is_foreign_key=field.name in relation_foreign_keys,
                    is_relation_field=is_relation,
                    relation_model=relation_model,
                    is_enum=field.type_name in enum_names,
                    default=_attribute_argument(default_attribute),
                    attributes=list(field.attributes),
                )
            )
        resolved_fields.sort(key=lambda item: item.name)
        return PrismaModel(
            name=model.name,
            source_file=source_file,
            primary_key=sorted(
                field.name for field in resolved_fields if field.is_primary_key
            ),
            unique_fields=sorted(field.name for field in resolved_fields if field.is_unique),
            fields=resolved_fields,
            model_attributes=sorted(model.model_attributes),
        )

    @staticmethod
    def _ownership_candidates(models: list[PrismaModel]) -> list[OwnershipCandidate]:
        candidates: list[OwnershipCandidate] = []
        for model in models:
            for field in model.fields:
                configured = _OWNERSHIP_PATTERNS.get(field.name.casefold())
                if configured is None:
                    continue
                candidate_type, base_confidence = configured
                evidence = ["Field name matches a configured ownership or tenancy pattern"]
                confidence = base_confidence
                if field.is_foreign_key and field.relation_model:
                    evidence.append(
                        f"Field is a foreign key for a relation to {field.relation_model}"
                    )
                    confidence = min(0.99, confidence + 0.03)
                candidates.append(
                    OwnershipCandidate(
                        model=model.name,
                        field=field.name,
                        candidate_type=candidate_type,
                        confidence=confidence,
                        evidence=evidence,
                    )
                )
        return sorted(candidates, key=lambda item: (item.model, item.field))

    @staticmethod
    def _property(body: str, name: str) -> str | None:
        for match in _ASSIGNMENT.finditer(body):
            if match.group(1) == name:
                return match.group(2)
        return None


def _parse_attributes(content: str) -> list[str]:
    attributes: list[str] = []
    index = 0
    while index < len(content):
        at = content.find("@", index)
        if at < 0:
            break
        name_match = re.match(r"@@?[A-Za-z_]\w*", content[at:])
        if name_match is None:
            index = at + 1
            continue
        end = at + len(name_match.group(0))
        if end < len(content) and content[end] == "(":
            closing = _matching_parenthesis(content, end)
            if closing is None:
                attributes.append(content[at:].strip())
                break
            end = closing + 1
        attributes.append(content[at:end])
        index = end
    return attributes


def _matching_parenthesis(content: str, opening: int) -> int | None:
    depth = 0
    quote = ""
    for index in range(opening, len(content)):
        character = content[index]
        if quote:
            if character == quote and (index == 0 or content[index - 1] != "\\"):
                quote = ""
        elif character in {'"', "'"}:
            quote = character
        elif character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return index
    return None


def _attribute_argument(attribute: str | None) -> str | None:
    if not attribute or "(" not in attribute or not attribute.endswith(")"):
        return None
    return attribute[attribute.find("(") + 1 : -1]


def _field_names(content: str) -> list[str]:
    return [part.strip() for part in content.split(",") if part.strip()]


def _mask_prisma_comments(content: str) -> str:
    return "\n".join(line.split("//", maxsplit=1)[0] for line in content.splitlines())


def _matching_brace(content: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(content)):
        if content[index] == "{":
            depth += 1
        elif content[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _line(content: str, position: int) -> int:
    return content.count("\n", 0, position) + 1
