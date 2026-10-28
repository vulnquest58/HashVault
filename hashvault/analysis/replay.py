"""Portable recipe serialization and deterministic replay."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Optional

from hashvault.analysis.operations import OPERATION_BY_NAME
from hashvault.analysis.recipe import AnalysisTrace, Layer

RECIPE_VERSION = 1


class RecipeReplayError(ValueError):
    pass


def recipe_to_dict(
    trace: AnalysisTrace,
    *,
    metadata: Optional[Mapping[str, Any]] = None,
) -> dict[str, Any]:
    required_keys: set[str] = set()
    layers = []
    for layer in trace.layers:
        operation = OPERATION_BY_NAME.get(layer.operation)
        if operation is not None:
            required_keys.update(operation.requires_keys)
        layers.append(
            {
                "operation": layer.operation,
                "category": layer.category,
                "depth": layer.depth,
                "input": layer.input_text,
                "output": layer.output_text,
                "confidence": round(layer.confidence, 4),
                "label": layer.label,
                "metadata": layer.metadata,
            }
        )
    result = {
        "version": RECIPE_VERSION,
        "raw_input": trace.raw_input,
        "finalized_input": trace.finalized_input,
        "chain": trace.describe(),
        "terminal": trace.terminal,
        "kind": trace.kind,
        "score": round(trace.score, 4),
        "required_keys": sorted(required_keys),
        "layers": layers,
    }
    if metadata:
        result["metadata"] = dict(metadata)
    return result


def recipe_from_dict(data: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(data, Mapping):
        raise ValueError("Recipe must be a JSON object")
    if int(data.get("version", RECIPE_VERSION)) > RECIPE_VERSION:
        raise ValueError("Unsupported recipe version")
    layers = data.get("layers")
    if not isinstance(layers, list):
        raise ValueError("Recipe must contain a layers list")
    normalized = []
    for index, layer in enumerate(layers, 1):
        if not isinstance(layer, Mapping) or not layer.get("operation"):
            raise ValueError(f"Invalid recipe layer at position {index}")
        normalized.append(
            {
                "operation": str(layer["operation"]),
                "category": str(layer.get("category", "Other")),
                "depth": int(layer.get("depth", index)),
                "input": str(layer.get("input", "")),
                "output": str(layer.get("output", "")),
                "confidence": float(layer.get("confidence", 0.0) or 0.0),
                "label": str(layer.get("label", "")),
                "metadata": layer.get("metadata") or {},
            }
        )
    return {
        **dict(data),
        "raw_input": str(data.get("raw_input", "")),
        "finalized_input": str(data.get("finalized_input", "")),
        "layers": normalized,
    }


def load_recipe(path: str | Path) -> dict[str, Any]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return recipe_from_dict(data)


def write_recipe(path: str | Path, recipe: Mapping[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(dict(recipe), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )


def replay_recipe(
    raw_input: str,
    recipe: Mapping[str, Any],
    *,
    keys: Optional[Mapping[str, str]] = None,
) -> AnalysisTrace:
    layers_data = recipe_from_dict(recipe)["layers"]
    current = raw_input
    layers: list[Layer] = []
    for index, layer_data in enumerate(layers_data, 1):
        name = layer_data["operation"]
        operation = OPERATION_BY_NAME.get(name)
        if operation is None:
            raise RecipeReplayError(f"Unknown recipe operation: {name}")
        try:
            outputs = operation.apply_many(current, keys or {})
        except Exception as exc:
            raise RecipeReplayError(f"Operation {name} failed: {exc}") from exc
        if not outputs:
            raise RecipeReplayError(
                f"Operation {name} produced no output at layer {index}"
            )
        expected = layer_data["output"]
        chosen = next((item for item in outputs if item.text == expected), outputs[0])
        layers.append(
            Layer(
                operation=name,
                input_text=current,
                output_text=chosen.text,
                confidence=float(layer_data["confidence"]),
                depth=index,
                category=str(layer_data["category"]),
                label=str(layer_data["label"]),
                metadata=dict(layer_data["metadata"]),
            )
        )
        current = chosen.text
    return AnalysisTrace(
        raw_input=raw_input,
        finalized_input=current,
        layers=layers,
        terminal=bool(recipe.get("terminal", False)),
        kind=str(recipe.get("kind", "text")),
    )
