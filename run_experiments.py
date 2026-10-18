#!/usr/bin/env python3
"""CKKS / TenSEAL benchmark with warm-ups and timing distributions.

Educational benchmark only; this is not a security audit.
"""

from __future__ import annotations

import argparse
import csv
import json
import platform
import random
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

import tenseal as ts

BASELINE = {
    "poly_modulus_degree": 8192,
    "coeff_mod_bit_sizes": [60, 40, 40, 60],
    "global_scale": 2**40,
}

TIMING_FIELDS = (
    "plaintext_eval",
    "encrypt_a",
    "encrypt_b",
    "encrypted_eval",
    "decrypt",
    "end_to_end",
)


def make_context(poly_modulus_degree: int = 8192):
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=poly_modulus_degree,
        coeff_mod_bit_sizes=BASELINE["coeff_mod_bit_sizes"],
    )
    context.global_scale = BASELINE["global_scale"]
    context.generate_relin_keys()
    context.generate_galois_keys()
    return context


def summarize_ms(samples: list[float]) -> dict[str, float | None]:
    if not samples:
        return {"min_ms": None, "median_ms": None, "p95_ms": None}
    ordered = sorted(samples)
    # Nearest-rank percentile: easy to describe and reproduce.
    p95_index = max(0, int(0.95 * len(ordered) + 0.999999) - 1)
    return {
        "min_ms": ordered[0],
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[min(p95_index, len(ordered) - 1)],
    }


def time_samples(fn: Callable[[], Any], warmups: int, repeats: int):
    for _ in range(warmups):
        fn()
    samples = []
    result = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        result = fn()
        samples.append((time.perf_counter_ns() - start) / 1_000_000)
    return summarize_ms(samples), result


def add_row(rows: list[dict[str, Any]], *, experiment: str, parameter_set: str,
            vector_length: int | None, expected: Any = None, actual: Any = None,
            absolute_error: float | None = None, relative_error: float | None = None,
            ciphertext_bytes: int | None = None, status: str = "ok", note: str = "",
            timings: dict[str, dict[str, float | None]] | None = None):
    row = {
        "experiment": experiment,
        "parameter_set": parameter_set,
        "vector_length": vector_length,
        "expected": json.dumps(expected) if isinstance(expected, (list, tuple)) else expected,
        "actual": json.dumps(actual) if isinstance(actual, (list, tuple)) else actual,
        "absolute_error": absolute_error,
        "relative_error": relative_error,
        "ciphertext_bytes": ciphertext_bytes,
        "status": status,
        "note": note,
    }
    for field in TIMING_FIELDS:
        stats = (timings or {}).get(field, {})
        for stat in ("min_ms", "median_ms", "p95_ms"):
            row[f"{field}_{stat}"] = stats.get(stat)
    rows.append(row)


def timed_stage(fn, warmups, repeats):
    stats, result = time_samples(fn, warmups, repeats)
    return stats, result


def run_worked_example(rows, warmups, repeats):
    context = make_context()
    a, b = [1.25, 2.0], [3.5, 4.0]
    expected = sum(x * y for x, y in zip(a, b))

    enc_a_stats, enc_a = timed_stage(lambda: ts.ckks_vector(context, a), warmups, repeats)
    enc_b_stats, enc_b = timed_stage(lambda: ts.ckks_vector(context, b), warmups, repeats)
    eval_stats, encrypted_result = timed_stage(lambda: enc_a.dot(enc_b), warmups, repeats)
    decrypt_stats, result = timed_stage(lambda: encrypted_result.decrypt(), warmups, repeats)
    plain_stats, plain = timed_stage(lambda: sum(x * y for x, y in zip(a, b)), warmups, repeats)

    actual = float(result[0])
    error = abs(actual - expected)
    # End-to-end timing is measured directly; it is not just a sum of stage medians.
    def end_to_end():
        left = ts.ckks_vector(context, a)
        right = ts.ckks_vector(context, b)
        return left.dot(right).decrypt()[0]
    e2e_stats, _ = timed_stage(end_to_end, warmups, repeats)

    timings = {
        "plaintext_eval": plain_stats,
        "encrypt_a": enc_a_stats,
        "encrypt_b": enc_b_stats,
        "encrypted_eval": eval_stats,
        "decrypt": decrypt_stats,
        "end_to_end": e2e_stats,
    }
    add_row(rows, experiment="worked_example_dot_product", parameter_set="baseline_8192",
            vector_length=2, expected=expected, actual=actual, absolute_error=error,
            relative_error=error / abs(expected), ciphertext_bytes=len(encrypted_result.serialize()),
            note="dot([1.25, 2.0], [3.5, 4.0]); end-to-end measured directly", timings=timings)


def run_add_mul(rows, warmups, repeats):
    context = make_context()
    a = [1.125, -2.25, 3.5, 0.125]
    b = [0.75, 4.0, -1.25, 2.5]
    enc_a, enc_b = ts.ckks_vector(context, a), ts.ckks_vector(context, b)

    cases = [
        ("addition", lambda: enc_a + enc_b, [x + y for x, y in zip(a, b)]),
        ("multiplication", lambda: enc_a * enc_b, [x * y for x, y in zip(a, b)]),
    ]
    for name, op, expected in cases:
        eval_stats, encrypted_result = timed_stage(op, warmups, repeats)
        decrypt_stats, actual = timed_stage(lambda: encrypted_result.decrypt(), warmups, repeats)
        plain_fn = (lambda: [x + y for x, y in zip(a, b)]) if name == "addition" else (
            lambda: [x * y for x, y in zip(a, b)]
        )
        plain_stats, _ = timed_stage(plain_fn, warmups, repeats)
        errors = [abs(float(x) - y) for x, y in zip(actual, expected)]
        add_row(rows, experiment=name, parameter_set="baseline_8192", vector_length=len(a),
                expected=expected, actual=actual, absolute_error=max(errors),
                ciphertext_bytes=len(encrypted_result.serialize()),
                note="input encryption excluded from evaluation timing",
                timings={"plaintext_eval": plain_stats, "encrypted_eval": eval_stats,
                         "decrypt": decrypt_stats})


def run_dot_scaling(rows, warmups, repeats, seed):
    rng = random.Random(seed)
    context = make_context()
    for length in (8, 32, 128, 512):
        a = [rng.uniform(-1, 1) for _ in range(length)]
        b = [rng.uniform(-1, 1) for _ in range(length)]
        expected = sum(x * y for x, y in zip(a, b))
        enc_a_stats, enc_a = timed_stage(lambda: ts.ckks_vector(context, a), warmups, repeats)
        enc_b_stats, enc_b = timed_stage(lambda: ts.ckks_vector(context, b), warmups, repeats)
        eval_stats, encrypted_result = timed_stage(lambda: enc_a.dot(enc_b), warmups, repeats)
        decrypt_stats, result = timed_stage(lambda: encrypted_result.decrypt(), warmups, repeats)
        plain_stats, _ = timed_stage(lambda: sum(x * y for x, y in zip(a, b)), warmups, repeats)
        actual = float(result[0])
        error = abs(actual - expected)

        def end_to_end():
            return ts.ckks_vector(context, a).dot(ts.ckks_vector(context, b)).decrypt()[0]
        e2e_stats, _ = timed_stage(end_to_end, warmups, repeats)

        add_row(rows, experiment="dot_product_scaling", parameter_set="baseline_8192",
                vector_length=length, expected=expected, actual=actual, absolute_error=error,
                relative_error=error / abs(expected) if abs(expected) > 1e-12 else None,
                ciphertext_bytes=len(encrypted_result.serialize()),
                note=f"fixed seed={seed}; inputs uniform in [-1, 1]",
                timings={"plaintext_eval": plain_stats, "encrypt_a": enc_a_stats,
                         "encrypt_b": enc_b_stats, "encrypted_eval": eval_stats,
                         "decrypt": decrypt_stats, "end_to_end": e2e_stats})


def run_depth(rows, warmups, repeats):
    # One fresh context per depth. A depth chain is a single dependent computation;
    # do not pretend the failed chain is a normal repeated timing sample.
    for depth in (1, 2, 3):
        try:
            context = make_context()
            encrypted = ts.ckks_vector(context, [1.01])
            expected = 1.01
            start = time.perf_counter_ns()
            for _ in range(depth):
                encrypted = encrypted * encrypted
                expected *= expected
            eval_ms = (time.perf_counter_ns() - start) / 1_000_000
            actual = float(encrypted.decrypt()[0])
            error = abs(actual - expected)
            add_row(rows, experiment="multiplicative_depth", parameter_set="baseline_8192",
                    vector_length=1, expected=expected, actual=actual, absolute_error=error,
                    relative_error=error / abs(expected) if expected else None,
                    ciphertext_bytes=len(encrypted.serialize()), note=f"repeated squaring count={depth}; single chain timing",
                    timings={"encrypted_eval": {"min_ms": eval_ms, "median_ms": eval_ms, "p95_ms": eval_ms}})
        except Exception as exc:
            add_row(rows, experiment="multiplicative_depth", parameter_set="baseline_8192",
                    vector_length=1, status="failed",
                    note=f"repeated squaring count={depth}; {type(exc).__name__}: {exc}")


def run_degree_comparison(rows, warmups, repeats):
    # Same coefficient-modulus bit sizes are retained for a simple observed
    # performance comparison. This is NOT a security-equivalent comparison.
    a = [0.1 * (i + 1) for i in range(32)]
    b = [0.05 * (i + 1) for i in range(32)]
    expected = sum(x * y for x, y in zip(a, b))
    plain_stats, _ = timed_stage(lambda: sum(x * y for x, y in zip(a, b)), warmups, repeats)

    for label, degree in (("degree_8192", 8192), ("degree_16384", 16384)):
        try:
            context = make_context(degree)
            enc_a_stats, enc_a = timed_stage(lambda: ts.ckks_vector(context, a), warmups, repeats)
            enc_b_stats, enc_b = timed_stage(lambda: ts.ckks_vector(context, b), warmups, repeats)
            eval_stats, encrypted_result = timed_stage(lambda: enc_a.dot(enc_b), warmups, repeats)
            decrypt_stats, result = timed_stage(lambda: encrypted_result.decrypt(), warmups, repeats)
            actual = float(result[0])
            error = abs(actual - expected)

            def end_to_end():
                return ts.ckks_vector(context, a).dot(ts.ckks_vector(context, b)).decrypt()[0]
            e2e_stats, _ = timed_stage(end_to_end, warmups, repeats)

            add_row(rows, experiment="polynomial_degree_comparison", parameter_set=label,
                    vector_length=len(a), expected=expected, actual=actual, absolute_error=error,
                    relative_error=error / abs(expected) if expected else None,
                    ciphertext_bytes=len(encrypted_result.serialize()),
                    note=f"degree={degree}; coeff_mod_bit_sizes={BASELINE['coeff_mod_bit_sizes']}; not security-equivalent",
                    timings={"plaintext_eval": plain_stats, "encrypt_a": enc_a_stats,
                             "encrypt_b": enc_b_stats, "encrypted_eval": eval_stats,
                             "decrypt": decrypt_stats, "end_to_end": e2e_stats})
        except Exception as exc:
            add_row(rows, experiment="polynomial_degree_comparison", parameter_set=label,
                    vector_length=len(a), status="failed", note=f"degree={degree}; {type(exc).__name__}: {exc}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--warmups", type=int, default=5)
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--seed", type=int, default=20261017)
    parser.add_argument("--output-dir", default="results")
    args = parser.parse_args()
    if args.warmups < 0 or args.repeats < 1:
        parser.error("--warmups must be >= 0 and --repeats must be >= 1")

    rows = []
    run_worked_example(rows, args.warmups, args.repeats)
    run_add_mul(rows, args.warmups, args.repeats)
    run_dot_scaling(rows, args.warmups, args.repeats, args.seed)
    run_depth(rows, args.warmups, args.repeats)
    run_degree_comparison(rows, args.warmups, args.repeats)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "results.json"
    csv_path = output_dir / "results.csv"

    metadata = {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "tenseal_version": getattr(ts, "__version__", "unknown"),
        "warmups": args.warmups,
        "repeats": args.repeats,
        "seed": args.seed,
        "baseline_parameters": BASELINE,
        "warning": "Educational benchmark only; not a security audit.",
        "rows": rows,
    }
    json_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    columns = list(rows[0].keys()) if rows else []
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        writer.writerows(rows)

    print(f"TenSEAL version: {metadata['tenseal_version']}")
    print(f"Python: {platform.python_version()} | warmups={args.warmups} | repeats={args.repeats}")
    print(f"Rows: {len(rows)}")
    print(f"CSV:  {csv_path.resolve()}")
    print(f"JSON: {json_path.resolve()}")
    print("\nStatus:")
    for row in rows:
        if row["experiment"] in ("worked_example_dot_product", "multiplicative_depth", "polynomial_degree_comparison"):
            print(f"  {row['experiment']:30s} {row['parameter_set']:16s} {row['status']:6s} {row['note']}")


if __name__ == "__main__":
    main()
