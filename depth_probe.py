#!/usr/bin/env python3
"""Probe CKKS repeated-squaring depth with two explicit TenSEAL configurations.

Educational experiment only, not a security audit.
"""
import argparse, csv, json, platform, sys, time
from datetime import datetime, timezone
from pathlib import Path
import tenseal as ts

CONFIGS = [
    {"name": "baseline_8192", "poly_modulus_degree": 8192,
     "coeff_mod_bit_sizes": [60, 40, 40, 60]},
    {"name": "extended_16384", "poly_modulus_degree": 16384,
     "coeff_mod_bit_sizes": [60, 40, 40, 40, 40, 60]},
]

def build_context(config):
    context = ts.context(ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=config["poly_modulus_degree"],
        coeff_mod_bit_sizes=config["coeff_mod_bit_sizes"])
    context.global_scale = 2**40
    context.generate_relin_keys()
    return context

def probe_config(config, max_depth):
    rows = []
    try:
        context = build_context(config)
        encrypted = ts.ckks_vector(context, [1.01])
        expected = 1.01
        actual = float(encrypted.decrypt()[0])
        rows.append({
            "config": config["name"], "poly_modulus_degree": config["poly_modulus_degree"],
            "coeff_mod_bit_sizes": json.dumps(config["coeff_mod_bit_sizes"]), "depth": 0,
            "status": "ok", "expected": expected, "actual": actual,
            "absolute_error": abs(actual - expected), "operation_ms": 0.0,
            "ciphertext_bytes": len(encrypted.serialize()), "note": "Initial encrypted value; depth 0"})
        for depth in range(1, max_depth + 1):
            start = time.perf_counter()
            try:
                encrypted = encrypted * encrypted
                elapsed_ms = (time.perf_counter() - start) * 1000
                expected *= expected
                actual = float(encrypted.decrypt()[0])
                rows.append({
                    "config": config["name"], "poly_modulus_degree": config["poly_modulus_degree"],
                    "coeff_mod_bit_sizes": json.dumps(config["coeff_mod_bit_sizes"]), "depth": depth,
                    "status": "ok", "expected": expected, "actual": actual,
                    "absolute_error": abs(actual - expected), "operation_ms": elapsed_ms,
                    "ciphertext_bytes": len(encrypted.serialize()),
                    "note": "One sequential encrypted squaring at this depth"})
            except Exception as exc:
                elapsed_ms = (time.perf_counter() - start) * 1000
                rows.append({
                    "config": config["name"], "poly_modulus_degree": config["poly_modulus_degree"],
                    "coeff_mod_bit_sizes": json.dumps(config["coeff_mod_bit_sizes"]), "depth": depth,
                    "status": "failed", "expected": None, "actual": None, "absolute_error": None,
                    "operation_ms": elapsed_ms, "ciphertext_bytes": None,
                    "note": f"{type(exc).__name__}: {exc}"})
                break
    except Exception as exc:
        rows.append({
            "config": config["name"], "poly_modulus_degree": config["poly_modulus_degree"],
            "coeff_mod_bit_sizes": json.dumps(config["coeff_mod_bit_sizes"]), "depth": 0,
            "status": "config_failed", "expected": None, "actual": None, "absolute_error": None,
            "operation_ms": None, "ciphertext_bytes": None,
            "note": f"{type(exc).__name__}: {exc}"})
    return rows

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-depth", type=int, default=6)
    parser.add_argument("--output-dir", default="results/depth_probe")
    args = parser.parse_args()
    if args.max_depth < 1:
        parser.error("--max-depth must be at least 1")
    rows = []
    for config in CONFIGS:
        rows.extend(probe_config(config, args.max_depth))
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    csv_path, json_path = out / "depth_probe.csv", out / "depth_probe.json"
    columns = ["config", "poly_modulus_degree", "coeff_mod_bit_sizes", "depth", "status",
               "expected", "actual", "absolute_error", "operation_ms", "ciphertext_bytes", "note"]
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)
    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version, "platform": platform.platform(),
        "machine": platform.machine(), "processor": platform.processor(),
        "tenseal_version": getattr(ts, "__version__", "unknown"),
        "global_scale": 2**40, "max_depth_requested": args.max_depth,
        "warning": "Educational depth probe only; not a security audit.", "rows": rows}
    json_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    print(f"TenSEAL version: {metadata['tenseal_version']}")
    print(f"CSV:  {csv_path.resolve()}")
    print(f"JSON: {json_path.resolve()}")
    print("\nDepth results:")
    for row in rows:
        print(f"{row['config']:18s} depth={row['depth']} status={row['status']:12s} "
              f"error={row['absolute_error']} size={row['ciphertext_bytes']} {row['note']}")

if __name__ == "__main__":
    main()
