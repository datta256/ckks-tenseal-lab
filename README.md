# CKKS + TenSEAL Lab — Experiment Record

This repository contains an exploratory, code-first investigation of approximate homomorphic arithmetic using **TenSEAL 0.3.16** and the CKKS scheme. The experiments were run on Windows with Python 3.12.10.

The purpose was to understand what encrypted arithmetic looks like in practice: whether computations can be evaluated on ciphertexts, how close decrypted results are to the expected values, how evaluation time and serialized ciphertext size behave, and how CKKS parameter choices affect a simple repeated-multiplication chain.

**Scope:** educational experiments for an explanatory article. This is not a cryptographic security audit, a production benchmark, or evidence that the chosen parameters are suitable for a particular threat model.

## Environment and main commands

The recorded runs used a local virtual environment at `.venv` and the pinned dependency:

```text
tenseal==0.3.16
```

The main benchmark was run with:

```powershell
.\.venv\Scripts\python.exe .\run_experiments.py --warmups 5 --repeats 30 --output-dir results\publication_run1
.\.venv\Scripts\python.exe .\run_experiments.py --warmups 5 --repeats 30 --output-dir results\publication_run2
```

Earlier exploratory runs were also saved under `results\`, `results\run2\`, and `results\run3\`. Results were kept in separate directories so later runs did not overwrite earlier outputs.

Depth experiments were run with:

```powershell
.\.venv\Scripts\python.exe .\depth_probe.py --max-depth 6 --output-dir results\depth_probe

.\.venv\Scripts\python.exe .\controlled_depth.py --max-depth 6 --output-dir results\depth_controlled
```

The controlled-depth experiment was repeated five times:

```powershell
1..5 | ForEach-Object {
    $out = "results\depth_repeat$_"
    Write-Host "`n===== RUN $_ =====" -ForegroundColor Cyan
    .\.venv\Scripts\python.exe .\controlled_depth.py `
        --max-depth 6 `
        --output-dir $out
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Run $_ failed with exit code $LASTEXITCODE" -ForegroundColor Red
        break
    }
}
```

A separate batched-timing experiment was also attempted. Its results are documented below but **are not used for the main performance conclusions**, because its timings changed materially with batch size and the cause was not established.

---

## Experiment 1 — Basic encrypted arithmetic

The main benchmark evaluates these cases:

- A worked dot product: `[1.25, 2.0] · [3.5, 4.0]`
- Element-wise addition on four values
- Element-wise multiplication on four values
- Dot products with vector lengths 8, 32, 128 and 512
- Repeated squaring to probe multiplicative depth
- A comparison between polynomial modulus degrees 8192 and 16384

For the ordinary arithmetic cases, input encryption, encrypted evaluation, decryption, and—in the dot-product cases—end-to-end execution are timed separately. The benchmark uses warm-up iterations and reports minimum, median, and p95 timing statistics. The depth chain is a single sequential computation, so its operation time is a single observation rather than a distribution.

### Representative results from the two publication runs

These are results from `results\publication_run1\results.csv` and `results\publication_run2\results.csv`. Timings are milliseconds. Errors are absolute differences between the decrypted approximate result and the expected plaintext result.

| Operation | Run 1 evaluation median | Run 2 evaluation median | Run 1 absolute error | Run 2 absolute error |
|---|---:|---:|---:|---:|
| Dot product, 2 elements | 3.1654 ms | 3.4135 ms | 1.90e-6 | 2.14e-6 |
| Addition, 4 elements | 0.0403 ms | 0.0402 ms | 4.37e-9 | 2.64e-9 |
| Multiplication, 4 elements | 2.4156 ms | 2.0560 ms | 1.21e-6 | 1.21e-6 |
| Dot product, 8 elements | 4.9343 ms | 4.8390 ms | 4.79e-7 | 6.13e-7 |
| Dot product, 32 elements | 7.0582 ms | 6.7565 ms | 6.35e-7 | 8.97e-7 |
| Dot product, 128 elements | 8.8541 ms | 8.7257 ms | 8.76e-7 | 5.71e-7 |
| Dot product, 512 elements | 10.7298 ms | 10.6075 ms | 1.42e-6 | 7.73e-7 |

For the two-element worked example, the measured end-to-end median was **9.525 ms** in run 1 and **10.262 ms** in run 2. End-to-end timing includes encryption, encrypted evaluation, and decryption; it is measured directly rather than calculated by adding the individual stage medians.

### What these measurements support

- The tested encrypted operations completed and returned decryptable results.
- The CKKS results were approximate rather than bit-for-bit identical to the plaintext results.
- In these runs, encrypted dot-product evaluation median increased from about 4.8–4.9 ms at length 8 to about 10.6–10.7 ms at length 512.
- The serialized result ciphertext for these dot products stayed close to **235 KB** across those lengths in this setup.
- The main dot-product evaluation timings for the two publication runs were reasonably similar. Individual measurements can still vary with runtime conditions and workload.

These are observations from this specific implementation, machine, parameter set, and workload. They should not be generalized to all CKKS implementations or hardware.

### Baseline CKKS parameters

The main benchmark's baseline context uses:

- Scheme: CKKS
- Polynomial modulus degree: `8192`
- Coefficient-modulus bit sizes: `[60, 40, 40, 60]`
- Global scale: `2**40`

The polynomial-degree comparison uses the same coefficient-modulus bit sizes with degrees 8192 and 16384. The script explicitly labels this comparison **not security-equivalent**. It is a simple observed runtime/size comparison, not a controlled comparison at equal security.

---

## Experiment 2 — Repeated squaring and multiplicative depth

The first depth probe compared two configurations:

| Configuration | Polynomial modulus degree | Coefficient-modulus bit sizes |
|---|---:|---|
| `baseline_8192` | 8192 | `[60, 40, 40, 60]` |
| `extended_16384` | 16384 | `[60, 40, 40, 40, 40, 60]` |

In that initial probe, the baseline configuration completed two sequential squarings and failed on the third with `ValueError: scale out of bounds`. The extended configuration completed four sequential squarings and failed on the fifth. Because both polynomial degree and coefficient-modulus chain changed in that comparison, the extra depth could not be attributed to the chain alone.

### Controlled follow-up

The controlled comparison kept polynomial modulus degree at `16384` and global scale at `2**40`, and changed the coefficient-modulus chain:

| Configuration | Coefficient-modulus bit sizes | Observed successful squarings |
|---|---|---:|
| Short chain | `[60, 40, 40, 60]` | 2 |
| Long chain | `[60, 40, 40, 40, 40, 60]` | 4 |

The controlled script was run five times. In **all five runs**, the short chain succeeded at depths 1 and 2 and failed at depth 3 with `ValueError: scale out of bounds`. In **all five runs**, the long chain succeeded at depths 1 through 4 and failed at depth 5 with the same exception.

The error after decryption grew with sequential squaring in the successful chain. In the five repeated runs, approximate absolute errors were around:

- Short chain, depth 1: `1.45e-6` to `1.46e-6`
- Short chain, depth 2: `6.27e-6` to `6.30e-6`
- Long chain, depth 3: `1.69e-5` to `1.70e-5`
- Long chain, depth 4: `4.21e-5` to `4.23e-5`

Ciphertext sizes also changed as the computation consumed the modulus chain. These serialized sizes are not measurements of peak RAM use.

### Interpretation and caveats

This demonstrates that the available multiplication depth depends on the selected CKKS parameters in this experiment. It does **not** establish a universal maximum depth for CKKS. The two chain configurations have different total coefficient-modulus sizes and are not a security-equivalent comparison. `ValueError: scale out of bounds` is the observed failure for these specific parameters and library version, not a universal CKKS error or limit.

---

## Experiment 3 — Polynomial modulus degree comparison

The main benchmark compared polynomial modulus degrees `8192` and `16384` for a 32-element dot product, using coefficient-modulus bit sizes `[60, 40, 40, 60]` in both cases.

In publication run 1:

| Degree | Evaluation median | Evaluation p95 | Serialized result size | Absolute error |
|---:|---:|---:|---:|---:|
| 8192 | 6.813 ms | 7.241 ms | 235,272 bytes | 8.38e-6 |
| 16384 | 15.416 ms | 18.667 ms | 460,209 bytes | 8.41e-5 |

In publication run 2, evaluation medians were 6.793 ms and 15.365 ms respectively, and serialized sizes were 235,326 bytes and 460,299 bytes.

The larger degree was slower and produced a larger serialized result in these runs. This is an observation under the chosen settings only. Since the comparison is explicitly not security-equivalent, it must not be presented as a fair comparison of performance at equal security.

---

## Experiment 4 — Batched timing attempt (excluded from conclusions)

A separate script, `batched_benchmark.py`, timed repeated operations on the same encrypted input objects. It was run with batch sizes 100 and 10.

For batch size 100, reported encrypted evaluation medians were approximately 14.30, 20.53, 25.89 and 31.56 ms for vector lengths 8, 32, 128 and 512. For batch size 10, the corresponding values were approximately 5.61, 7.22, 9.77 and 32.31 ms.

These results changed materially with batch size and did not align consistently with the original benchmark. The script repeatedly evaluates the same ciphertext objects; whether repeated evaluation/state behavior, timing methodology, or other factors explain the discrepancy was not established during this project.

**Decision:** do not use these batched timings or their slowdown ratios as final performance claims. They are retained as an inconclusive exploratory attempt, not as validated throughput results. No claim is made here about the precise cause of the discrepancy.

---

## Reproducibility and interpretation notes

- The main benchmark uses `time.perf_counter_ns()` to time individual function calls, with warm-up calls before measured samples.
- It reports min, median and p95 for repeated stages. The p95 is an observed sample percentile, not a worst-case latency guarantee.
- The depth experiment is a sequential dependency chain and records a single timing per successful depth operation.
- Plaintext timings are extremely small for some operations. Ratios between encrypted and plaintext times can be sensitive to timer resolution and Python overhead; report absolute timings alongside ratios.
- The `ciphertext_bytes` field is the size of the serialized ciphertext returned by TenSEAL, not total memory use, network transfer cost for an entire application, or key-storage overhead.
- The error metric is the absolute difference between the decrypted approximate result and the expected result for the tested inputs. It is not a general error bound.
- The parameter sets were not independently audited for security, and the experiments do not establish suitability for any deployment or threat model.
- The repository does not implement a complete private inference system. These experiments focus on arithmetic primitives and parameter behavior.

## Main files

- `run_experiments.py` — arithmetic, dot-product scaling, single-run depth probe, and polynomial-degree comparison.
- `depth_probe.py` — initial depth comparison where polynomial degree and modulus chain both vary.
- `controlled_depth.py` — fixed-degree comparison between short and long coefficient-modulus chains.
- `batched_benchmark.py` — exploratory repeated-evaluation timing attempt; results excluded from the main performance conclusions.
- `results/publication_run1/` and `results/publication_run2/` — two publication benchmark runs.
- `results/depth_probe/` — initial depth-probe results.
- `results/depth_controlled/` and `results/depth_repeat1/` through `results/depth_repeat5/` — controlled depth comparison and five repeated runs.
- `results/batched_benchmark.json` and `results/batched_benchmark_batch10.json` — inconclusive batched-timing attempt.
- `requirements.txt` — dependency pin for TenSEAL.

## Bottom line

The experiments provide a reproducible educational demonstration that TenSEAL can evaluate selected arithmetic operations on CKKS ciphertexts, that decryption returns approximate numerical results, and that the tested parameter chains behave differently under sequential squaring. They also provide machine-specific timing and serialized-size observations.

They do not constitute a security audit, a general-purpose CKKS performance study, a security-equivalent parameter comparison, or a production-readiness claim.
