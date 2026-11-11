"""Strict validation of tools/call arguments (Phase 8).

WHY THIS IS NOT A JSON SCHEMA LIBRARY, and must not become one.

Phase 8 adds no runtime dependencies, so there is no `jsonschema` here. The
response to that constraint is NOT to write a general-purpose validator --
a half-implemented JSON Schema engine is worse than none, because callers
start trusting keywords it silently ignores.

Instead this validates a deliberately NARROW subset, and refuses anything
outside it. The protected tool specs in this system use exactly that subset
(`type: object`, `properties`, `required`, and scalar property types), so
nothing is lost today; and if a future tool declares a schema this cannot
fully enforce, `validate_arguments` REFUSES THE TOOL rather than waving the
call through. An unenforceable schema is treated as a closed door, which is
the only safe direction for a validator to fail in.

THE ALLOW-LIST RULE. Unknown argument names are rejected, not ignored. A
permissive validator that drops unrecognised fields invites a caller to
smuggle one past review in the hope that some layer downstream reads it;
rejecting means the set of arguments that reaches a handler is exactly the
set the schema declared.

WHAT THIS DOES NOT DECIDE: whether the agent may call the tool, whether the
resource exists, or whether the values are permitted. Those are policy's,
and asking them here would create a second opinion that could disagree with
Rego.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# The property types this validator can actually enforce. A schema using
# anything else is refused rather than partially checked.
_SUPPORTED_TYPES = {"string", "integer", "number", "boolean", "object", "array"}

# Schema keywords this validator understands at the top level. Any other
# keyword means the schema says something this code cannot enforce.
_SUPPORTED_ROOT_KEYS = {"type", "properties", "required", "title", "description",
                        "additionalProperties"}
# Per-property keywords that are purely descriptive and safe to ignore.
_DESCRIPTIVE_PROPERTY_KEYS = {"description", "title", "examples", "default"}


@dataclass
class ArgumentValidation:
    ok: bool
    arguments: dict[str, Any] = field(default_factory=dict)
    reason: str | None = None
    detail: str | None = None


def _type_matches(value: Any, declared: str) -> bool:
    if declared == "string":
        return isinstance(value, str)
    if declared == "integer":
        # `isinstance(True, int)` is True in Python. A boolean passed where
        # an integer is declared is a type confusion, not a convenience.
        return isinstance(value, int) and not isinstance(value, bool)
    if declared == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if declared == "boolean":
        return isinstance(value, bool)
    if declared == "object":
        return isinstance(value, dict)
    if declared == "array":
        return isinstance(value, list)
    return False


def validate_arguments(
    schema: dict[str, Any] | None, arguments: Any
) -> ArgumentValidation:
    """Validate `arguments` against a tool's declared `inputSchema`.

    Returns the validated arguments on success. The returned dict is a fresh
    copy containing ONLY declared properties, so a caller cannot accidentally
    forward something the schema did not describe.
    """
    from app.protocols.mcp.service import MCPReason

    if arguments is None:
        arguments = {}
    if not isinstance(arguments, dict):
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
            detail="arguments must be an object",
        )

    if not isinstance(schema, dict):
        # A tool with no enforceable schema is not callable over this
        # transport. Fail closed.
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
            detail="this tool does not declare a schema this server can enforce",
        )

    unsupported_root = set(schema) - _SUPPORTED_ROOT_KEYS
    if unsupported_root or schema.get("type") != "object":
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
            detail="this tool does not declare a schema this server can enforce",
        )

    properties = schema.get("properties") or {}
    if not isinstance(properties, dict):
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
            detail="this tool does not declare a schema this server can enforce",
        )

    required = schema.get("required") or []
    if not isinstance(required, list) or not all(isinstance(r, str) for r in required):
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
            detail="this tool does not declare a schema this server can enforce",
        )

    # THE ALLOW-LIST. Checked before anything else is read, so an unexpected
    # name is refused rather than inspected.
    unknown = sorted(set(arguments) - set(properties))
    if unknown:
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_UNKNOWN_FIELD,
            detail=f"unexpected argument(s): {', '.join(unknown)}",
        )

    missing = sorted(name for name in required if name not in arguments)
    if missing:
        return ArgumentValidation(
            ok=False, reason=MCPReason.ARGUMENTS_MISSING_REQUIRED,
            detail=f"missing required argument(s): {', '.join(missing)}",
        )

    validated: dict[str, Any] = {}
    for name, value in arguments.items():
        spec = properties.get(name)
        if not isinstance(spec, dict):
            return ArgumentValidation(
                ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
                detail="this tool does not declare a schema this server can enforce",
            )
        declared = spec.get("type")
        if declared not in _SUPPORTED_TYPES:
            # The schema constrains this property in a way this validator
            # cannot check. Refuse rather than accept unchecked.
            return ArgumentValidation(
                ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
                detail="this tool does not declare a schema this server can enforce",
            )
        unsupported = set(spec) - _DESCRIPTIVE_PROPERTY_KEYS - {"type"}
        if unsupported:
            return ArgumentValidation(
                ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
                detail="this tool does not declare a schema this server can enforce",
            )
        if not _type_matches(value, declared):
            return ArgumentValidation(
                ok=False, reason=MCPReason.ARGUMENTS_MALFORMED,
                detail=f"argument {name!r} must be of type {declared}",
            )
        validated[name] = value

    return ArgumentValidation(ok=True, arguments=validated)
