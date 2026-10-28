"""
Router — decides which external engine should crack an identified hash.

Layer 6 of the deep-analysis pipeline. Consults the canonicalized payload's
tool capability (hashcat mode present? john format present?), the user's
explicit tool choice, and the configured default strategy to pick the best
execution backend — leaving a clean plug-point for a future unified engine.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from hashvault.core.canonicalizer import ToolCapability
from hashvault.core.registry import CrackTool
from hashvault.exceptions import ToolSelectionError


@dataclass
class RouteDecision:
    """Result of tool routing."""

    tool: CrackTool
    capability: ToolCapability
    reason: str

    def summary(self) -> str:
        return f"{self.tool.value} ({self.reason})"


def route_tool(
    capability: ToolCapability,
    *,
    requested: Optional[CrackTool] = None,
    default_tool: CrackTool = CrackTool.HASHCAT,
    prefer_john: bool = False,
    hashcat_available: bool = True,
    john_available: bool = True,
    builtin_available: bool = True,
) -> RouteDecision:
    """
    Pick the tool for a payload.

    Rules
    -----
    * An explicit ``requested`` tool is honoured when it is supported and the
      engine is available; otherwise a ToolSelectionError is raised.
    * AUTO picks hashcat first (fastest), then John, then the built-in engine,
      unless ``prefer_john`` is set.
    * A tool is only chosen when the pattern exposes the needed mode/format.
    """
    if capability is None:
        capability = ToolCapability()

    if requested is not None and not isinstance(requested, CrackTool):
        try:
            requested = CrackTool(str(requested).lower())
        except ValueError as exc:
            raise ToolSelectionError(f"Unknown tool: {requested!r}") from exc
    if not isinstance(default_tool, CrackTool):
        try:
            default_tool = CrackTool(str(default_tool).lower())
        except ValueError as exc:
            raise ToolSelectionError(f"Unknown default tool: {default_tool!r}") from exc

    def usable(tool: CrackTool) -> bool:
        if tool == CrackTool.HASHCAT:
            return capability.hashcat and hashcat_available
        if tool == CrackTool.JOHN:
            return capability.john and john_available
        if tool == CrackTool.BUILTIN:
            return capability.builtin and builtin_available
        return False

    if requested is not None and requested != CrackTool.AUTO:
        if not usable(requested):
            if requested == CrackTool.HASHCAT:
                detail = "no hashcat mode" if not capability.hashcat else "hashcat is not available"
            elif requested == CrackTool.JOHN:
                detail = "no john format" if not capability.john else "john is not available"
            else:
                detail = (
                    "no built-in verifier"
                    if not capability.builtin
                    else "built-in engine is disabled"
                )
            raise ToolSelectionError(f"{requested.value.upper()} requested but {detail}.")
        return RouteDecision(requested, capability, "explicit request")

    if requested == CrackTool.AUTO:
        order = [CrackTool.JOHN, CrackTool.HASHCAT] if prefer_john else [CrackTool.HASHCAT, CrackTool.JOHN]
        for tool in order:
            if usable(tool):
                reason = "auto-selected" if usable(order[0]) and usable(order[1]) else f"{tool.value} present"
                return RouteDecision(tool, capability, reason)
        if usable(CrackTool.BUILTIN):
            return RouteDecision(CrackTool.BUILTIN, capability, "built-in verifier present")
        raise ToolSelectionError(
            "No engine supports this hash type (no hashcat mode, john format, "
            "or built-in verifier available)."
        )

    # requested is None -> fall back to configured default.
    eff = default_tool
    if eff == CrackTool.AUTO:
        return route_tool(
            capability,
            requested=CrackTool.AUTO,
            prefer_john=prefer_john,
            hashcat_available=hashcat_available,
            john_available=john_available,
            builtin_available=builtin_available,
        )

    fallback_order = [eff] + [t for t in (CrackTool.HASHCAT, CrackTool.JOHN, CrackTool.BUILTIN) if t != eff]
    for tool in fallback_order:
        if usable(tool):
            reason = f"configured default ({eff.value})" if tool == eff else f"default {eff.value} unavailable -> {tool.value}"
            return RouteDecision(tool, capability, reason)
    # Default tool unusable and no fallback target -> error.
    raise ToolSelectionError(
        f"Default tool {eff.value} cannot handle this hash type and no "
        "supported fallback exists."
    )


def route_for_pattern(pattern, **kwargs) -> RouteDecision:
    """Convenience: route straight from a pattern (uses its capability)."""
    from hashvault.core.canonicalizer import capability_for
    return route_tool(capability_for(pattern), **kwargs)
