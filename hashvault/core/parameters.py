"""Offline password-hash parameter inspection and cost estimation."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from typing import Any, Optional


@dataclass
class ParameterReport:
    format: str
    parameters: dict[str, Any] = field(default_factory=dict)
    work_factor: Optional[float] = None
    cost_class: str = "unknown"
    is_slow: bool = False
    warnings: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _int(value: Any, default: Optional[int] = None) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _cost_class(work_factor: Optional[float]) -> str:
    if work_factor is None:
        return "unknown"
    if work_factor < 10_000:
        return "low"
    if work_factor < 1_000_000:
        return "moderate"
    if work_factor < 100_000_000:
        return "high"
    return "very_high"


def _finalize(report: ParameterReport) -> ParameterReport:
    report.cost_class = _cost_class(report.work_factor)
    report.is_slow = (
        report.is_slow
        or report.cost_class in {"high", "very_high"}
        or bool(report.parameters.get("is_slow"))
    )
    if report.is_slow:
        report.recommendations.append("Cap audit time and use targeted guess generation.")
    if report.cost_class == "low":
        report.recommendations.append("The stored hash uses weak work-factor settings.")
    if not report.parameters.get("salt") and report.format not in {
        "raw-md5",
        "raw-sha1",
        "raw-sha256",
        "raw-sha512",
        "ntlm",
    }:
        report.warnings.append("No explicit salt parameter was found in the encoding.")
    return report


def analyze_parameters(hash_value: str) -> ParameterReport:
    value = (hash_value or "").strip()
    if not value:
        return _finalize(ParameterReport(format="empty", warnings=["Empty hash value."]))

    bcrypt = re.match(r"^\$2([abxy])\$(\d{1,2})\$", value)
    if bcrypt:
        cost = _int(bcrypt.group(2), 0) or 0
        work = float(2 ** cost)
        return _finalize(
            ParameterReport(
                format="bcrypt",
                parameters={
                    "variant": f"2{bcrypt.group(1)}",
                    "cost": cost,
                    "work_factor": work,
                    "salt": value.split("$")[3] if value.count("$") >= 3 else None,
                },
                work_factor=work,
                is_slow=cost >= 10,
            )
        )

    sha_crypt = re.match(r"^\$([56])\$(?:rounds=(\d+)\$)?", value)
    if sha_crypt:
        algorithm = "sha256crypt" if sha_crypt.group(1) == "5" else "sha512crypt"
        rounds = _int(sha_crypt.group(2), 5000) or 5000
        parts = value.split("$")
        return _finalize(
            ParameterReport(
                format=algorithm,
                parameters={
                    "rounds": rounds,
                    "salt": parts[2] if len(parts) > 2 else None,
                },
                work_factor=float(rounds),
                is_slow=rounds >= 100_000,
            )
        )

    django = re.match(r"^pbkdf2_(sha\d+)\$(\d+)\$([^$]*)\$", value)
    if django:
        iterations = _int(django.group(2), 0) or 0
        return _finalize(
            ParameterReport(
                format=f"django-pbkdf2-{django.group(1)}",
                parameters={
                    "iterations": iterations,
                    "salt": django.group(3),
                },
                work_factor=float(iterations),
                is_slow=iterations >= 100_000,
            )
        )

    mirth = re.match(r"^(sha256|sha512|sha1):(\d+):([^:]+):", value, re.IGNORECASE)
    if mirth:
        iterations = _int(mirth.group(2), 0) or 0
        return _finalize(
            ParameterReport(
                format=f"pbkdf2-{mirth.group(1).lower()}",
                parameters={
                    "iterations": iterations,
                    "salt": mirth.group(3),
                },
                work_factor=float(iterations),
                is_slow=iterations >= 100_000,
            )
        )

    phc = re.match(r"^\$pbkdf2-(sha\d+)\$([^$]+)\$", value)
    if phc:
        params = phc.group(2)
        iterations = None
        if "=" in params:
            for part in params.split(","):
                key, _, raw = part.partition("=")
                if key.strip() == "i":
                    iterations = _int(raw)
        else:
            iterations = _int(params)
        iterations = iterations or 0
        return _finalize(
            ParameterReport(
                format=f"pbkdf2-{phc.group(1)}",
                parameters={"iterations": iterations, "encoding": "PHC"},
                work_factor=float(iterations),
                is_slow=iterations >= 100_000,
            )
        )

    argon2 = re.match(r"^\$argon2(id|i|d)\$v=(\d+)\$([^$]+)\$", value)
    if argon2:
        params: dict[str, Any] = {}
        for part in argon2.group(3).split(","):
            key, _, raw = part.partition("=")
            parsed = _int(raw)
            params[key] = parsed if parsed is not None else raw
        memory = _int(params.get("m"), 0) or 0
        time_cost = _int(params.get("t"), 0) or 0
        parallelism = _int(params.get("p"), 1) or 1
        work = float(max(1, memory * time_cost * parallelism))
        return _finalize(
            ParameterReport(
                format=f"argon2{argon2.group(1)}",
                parameters={
                    "version": _int(argon2.group(2)),
                    "memory_kib": memory,
                    "time_cost": time_cost,
                    "parallelism": parallelism,
                },
                work_factor=work,
                is_slow=True,
            )
        )

    scrypt = re.match(r"^\$scrypt\$([^$]+)\$", value)
    if scrypt:
        params: dict[str, Any] = {}
        for part in scrypt.group(1).split(","):
            key, _, raw = part.partition("=")
            parsed = _int(raw)
            params[key] = parsed if parsed is not None else raw
        ln = _int(params.get("ln"), 0) or 0
        r = _int(params.get("r"), 1) or 1
        p = _int(params.get("p"), 1) or 1
        n = 2 ** ln
        work = float(n * r * p)
        return _finalize(
            ParameterReport(
                format="scrypt",
                parameters={
                    "ln": ln,
                    "n": n,
                    "r": r,
                    "p": p,
                },
                work_factor=work,
                is_slow=work >= 100_000,
            )
        )

    cisco8 = re.match(r"^\$8\$(\d+)\$([^$]+)\$", value)
    if cisco8:
        iterations = _int(cisco8.group(1), 0) or 0
        return _finalize(
            ParameterReport(
                format="cisco-type8-pbkdf2-sha256",
                parameters={"iterations": iterations, "salt": cisco8.group(2)},
                work_factor=float(iterations),
                is_slow=iterations >= 100_000,
            )
        )

    if re.fullmatch(r"[0-9a-fA-F]{32}", value):
        return _finalize(ParameterReport(format="raw-md5", parameters={"salt": None}))
    if re.fullmatch(r"[0-9a-fA-F]{40}", value):
        return _finalize(ParameterReport(format="raw-sha1", parameters={"salt": None}))
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        platform = "unknown"
        return _finalize(
            ParameterReport(
                format="raw-sha256-or-equivalent",
                parameters={"salt": None, "candidate": platform},
            )
        )
    if re.fullmatch(r"[0-9a-fA-F]{128}", value):
        return _finalize(ParameterReport(format="raw-sha512", parameters={"salt": None}))

    return _finalize(
        ParameterReport(
            format="unknown",
            warnings=["No recognized parameterized hash encoding."],
            recommendations=[
                "Run `hashvault analyze` or `hashvault identify` to classify the input."
            ],
        )
    )
