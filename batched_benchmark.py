import argparse
import json
import platform
import statistics
import time
from pathlib import Path

import tenseal as ts

def make_context():
    context = ts.context(
        ts.SCHEME_TYPE.CKKS,
        poly_modulus_degree=8192,
        coeff_mod_bit_sizes=[60, 40, 40, 60],
    )
    context.global_scale = 2**40
    context.generate_galois_keys()
    context.generate_relin_keys()
    return context

def measure_batch(fn, warmups, repeats, batch_size):
    for _ in range(warmups):
        for _ in range(batch_size):
            fn()

    samples = []
    result = None
    for _ in range(repeats):
        start = time.perf_counter_ns()
        for _ in range(batch_size):
            result = fn()
        elapsed_ms = (time.perf_counter_ns() - start) / 1_000_000
        samples.append(elapsed_ms / batch_size)

    ordered = sorted(samples)
    p95_index = min(len(ordered) - 1, int(0.95 * len(ordered)))
    return {
        "median_ms_per_operation": statistics.median(samples),
        "p95_ms_per_operation": ordered[p95_index],
        "min_ms_per_operation": min(samples),
        "samples": len(samples),
        "batch_size": batch_size,
    }, result

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--warmups", type=int, default=3)
    parser.add_argument("--repeats", type=int, default=20)
    parser.add_argument("--batch-size", type=int, default=100)
    parser.add_argument("--output", default="results/batched_benchmark.json")
    args = parser.parse_args()

    if args.warmups < 0 or args.repeats < 2 or args.batch_size < 1:
        parser.error("Use warmups >= 0, repeats >= 2, batch-size >= 1")

    context = make_context()
    results = []

    for length in (8, 32, 128, 512):
        # Deterministic, bounded inputs for reproducibility.
        a = [((i % 17) - 8) / 10 for i in range(length)]
        b = [((i % 13) - 6) / 10 for i in range(length)]
        expected = sum(x * y for x, y in zip(a, b))

        enc_a = ts.ckks_vector(context, a)
        enc_b = ts.ckks_vector(context, b)

        plain_stats, plain_result = measure_batch(
            lambda: sum(x * y for x, y in zip(a, b)),
            args.warmups, args.repeats, args.batch_size,
        )
        encrypted_stats, encrypted_result = measure_batch(
            lambda: enc_a.dot(enc_b),
            args.warmups, args.repeats, args.batch_size,
        )

        actual = float(encrypted_result.decrypt()[0])
        error = abs(actual - expected)
        results.append({
            "vector_length": length,
            "expected": expected,
            "actual": actual,
            "absolute_error": error,
            "plaintext": plain_stats,
            "encrypted_evaluation": encrypted_stats,
            "ciphertext_bytes": len(encrypted_result.serialize()),
            "slowdown_ratio_median": (
                encrypted_stats["median_ms_per_operation"]
                / plain_stats["median_ms_per_operation"]
                if plain_stats["median_ms_per_operation"] > 0 else None
            ),
        })

    payload = {
        "tenseal_version": getattr(ts, "__version__", "unknown"),
        "python_version": platform.python_version(),
        "poly_modulus_degree": 8192,
        "coeff_mod_bit_sizes": [60, 40, 40, 60],
        "global_scale": 2**40,
        "warmups": args.warmups,
        "repeats": args.repeats,
        "batch_size": args.batch_size,
        "timing_unit": "milliseconds per operation, averaged over each batch",
        "results": results,
    }

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"TenSEAL: {payload['tenseal_version']} | Python: {payload['python_version']}")
    print(f"Saved: {output.resolve()}")
    for row in results:
        print(
            f"n={row['vector_length']:>3} "
            f"plain={row['plaintext']['median_ms_per_operation']:.6f} ms "
            f"encrypted={row['encrypted_evaluation']['median_ms_per_operation']:.6f} ms "
            f"ratio={row['slowdown_ratio_median']:.1f}x "
            f"error={row['absolute_error']:.3e} "
            f"size={row['ciphertext_bytes']} bytes"
        )

if __name__ == "__main__":
    main()
