from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from app.native.bridge import get_native_bridge

SPARK_CHARS = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]


def render_ascii_sparkline(values: list[float], min_val: float = 0.0, max_val: float = 8.0) -> str:
    """Render a sequence of float values as a terminal Unicode sparkline."""
    if not values:
        return ""
    diff = max_val - min_val if max_val > min_val else 1.0
    out = []
    for v in values:
        normalized = max(0.0, min(1.0, (v - min_val) / diff))
        idx = int(normalized * (len(SPARK_CHARS) - 1))
        out.append(SPARK_CHARS[idx])
    return "".join(out)


def render_entropy_bars(values: list[float], rows: int = 6) -> str:
    """Render a multi-row ASCII density heat bar for terminal presentation."""
    if not values:
        return ""
    lines = []
    # Sample down to max 60 columns
    cols = min(60, len(values))
    step = len(values) / cols
    sampled = [values[int(i * step)] for i in range(cols)]

    for row in range(rows - 1, -1, -1):
        threshold = (row / rows) * 8.0
        line_chars = []
        for v in sampled:
            if v >= threshold + (8.0 / rows):
                line_chars.append("█")
            elif v >= threshold:
                line_chars.append("▄")
            else:
                line_chars.append(" ")
        lines.append(f"{threshold:3.1f} |" + "".join(line_chars))
    lines.append("    +" + "-" * cols)
    lines.append(f"    0.0{' ' * (cols - 8)}offset")
    return "\n".join(lines)


def analyze_sliding_entropy(
    file_path: Path | str,
    window_size: int = 512,
    step_size: int = 128,
    visualize: bool = False,
) -> dict[str, Any]:
    """Analyze Shannon and sliding-window entropy across a binary file."""
    path = Path(file_path)
    if not path.is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    data = path.read_bytes()
    bridge = get_native_bridge()

    overall_entropy = bridge.calculate_entropy(data)
    curve = bridge.sliding_window_entropy(data, window_size=window_size, step_size=step_size)

    if not curve:
        curve = [overall_entropy]

    min_ent = min(curve)
    max_ent = max(curve)
    avg_ent = sum(curve) / len(curve)

    variance = sum((x - avg_ent) ** 2 for x in curve) / len(curve)
    std_dev = math.sqrt(variance)

    # Detect high-entropy suspect zones (likely packed or encrypted)
    packed_blocks = []
    for idx, ent in enumerate(curve):
        if ent >= 7.2:
            offset = idx * step_size
            packed_blocks.append({"index": idx, "offset": offset, "entropy": ent})

    sparkline = render_ascii_sparkline(curve)
    ascii_graph = render_entropy_bars(curve) if visualize else ""

    # Assess packing likelihood
    is_packed = overall_entropy >= 7.2 or (len(packed_blocks) / len(curve)) > 0.35
    risk_level = "high" if is_packed else ("medium" if overall_entropy >= 6.5 else "low")

    return {
        "file": str(path),
        "file_size": len(data),
        "overall_entropy": overall_entropy,
        "window_size": window_size,
        "step_size": step_size,
        "total_points": len(curve),
        "min_entropy": round(min_ent, 4),
        "max_entropy": round(max_ent, 4),
        "mean_entropy": round(avg_ent, 4),
        "standard_deviation": round(std_dev, 4),
        "packed_block_count": len(packed_blocks),
        "packing_assessment": {
            "is_packed_or_encrypted": is_packed,
            "risk_level": risk_level,
            "confidence": "high" if len(curve) > 20 else "medium",
            "indicator": "High entropy (>7.2 bits/byte) indicates compression, encryption, or packing." if is_packed else "Normal entropy distribution.",
        },
        "sparkline": sparkline,
        "ascii_graph": ascii_graph,
        "entropy_curve": curve[:500],  # cap curve in json to 500 samples
    }
