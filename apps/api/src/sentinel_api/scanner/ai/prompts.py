"""Minimal prompts built only from approved structured finding data."""

import hashlib
import json
from dataclasses import dataclass

from sentinel_api.scanner.ai.formatter import AIModelOutput
from sentinel_api.scanner.analysis.models import (
    AuthorizationFinding,
    AuthorizationGraph,
)
from sentinel_api.scanner.discovery.models import DiscoveredRoute

PROMPT_VERSION = "sentinel-ai-explanation-v1"
SYSTEM_PROMPT = """You are a Senior Application Security Engineer.
The deterministic Sentinel scanner is the sole authority on whether a finding exists.
Explain only the supplied finding. Never invent, add, remove, downgrade, or contradict findings.
Never fabricate evidence. Never suggest exploitation, attack payloads, malware, or offensive steps.
Produce concise plain text in the structured schema; do not use Markdown or HTML.
For business impact, address developers, security teams, and management in plain language.
Propose one minimal unified diff for the declared source file only. Never remove authentication,
validation, authorization, or security middleware. Never produce destructive changes.
The patch is a review-required proposal and must not claim to have been applied or verified.
The verification checklist must include ownership enforcement, authenticated identity use,
unauthorized-user behavior, regression tests, human review, and a deterministic scanner rerun."""


@dataclass(frozen=True, slots=True)
class PromptRequest:
    """Provider-neutral prompt with a deterministic cache hash."""

    system: str
    user: str
    prompt_hash: str


def build_prompt(
    finding: AuthorizationFinding,
    route: DiscoveredRoute,
    graph: AuthorizationGraph,
    model: str,
) -> PromptRequest:
    """Build a prompt without repository content, secrets, or absolute paths."""
    if finding.source_file.startswith(("/", "\\")):
        raise ValueError("Finding source path must be relative before AI use")
    payload = {
        "finding": {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "category": finding.category,
            "severity": finding.severity,
            "confidence": finding.confidence,
            "operation": finding.operation,
            "ownership_candidate": finding.ownership_candidate,
            "source_file": finding.source_file,
            "description": finding.description,
        },
        "route": {
            "route_id": route.route_id,
            "method": route.method,
            "path": route.path,
            "authentication_required": route.authentication_required,
            "authentication_middleware": route.authentication_middleware,
        },
        "model": finding.model,
        "evidence": finding.evidence,
        "risk": {
            "score": finding.risk_score,
            "components": [item.model_dump() for item in finding.risk_components],
        },
        "recommendation": finding.recommendation,
        "authorization_graph_summary": {
            "decision": graph.decision,
            "nodes": [
                {"type": node.type, "value": node.value} for node in graph.nodes
            ],
            "relationships": sorted({edge.relationship for edge in graph.edges}),
        },
        "output_contract": AIModelOutput.__name__,
    }
    user = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    fingerprint = "\n".join((PROMPT_VERSION, model, SYSTEM_PROMPT, user))
    prompt_hash = hashlib.sha256(fingerprint.encode("utf-8")).hexdigest()
    return PromptRequest(system=SYSTEM_PROMPT, user=user, prompt_hash=prompt_hash)
