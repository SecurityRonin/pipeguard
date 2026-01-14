//! Memory Profiling Benchmark
//!
//! Measures peak memory usage, heap allocations, and memory growth
//! across different payload sizes. Uses macOS-specific APIs when available.

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use std::time::Duration;
use std::process::{Command, Stdio};
use std::io::Write;
use std::path::PathBuf;

/// Sample sizes for memory testing
const SAMPLE_SIZES: &[usize] = &[
    100,      // 100 bytes
    1_000,    // 1 KB
    10_000,   // 10 KB
    100_000,  // 100 KB
    1_000_000, // 1 MB (stress test)
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

/// Generate payload of specified size
fn generate_payload(size: usize) -> String {
    let base = "echo 'Processing data...'\n";
    base.repeat((size / base.len()).max(1))
}

/// Get memory usage from /usr/bin/time on macOS
#[cfg(target_os = "macos")]
fn measure_memory(content: &str) -> Option<MemoryUsage> {
    use std::process::Command;

    // Use /usr/bin/time -l to get memory stats on macOS
    let output = Command::new("/usr/bin/time")
        .arg("-l")
        .arg(get_pipeguard_binary())
        .arg("scan")
        .arg("--rules")
        .arg(get_rules_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;

    output.stdin.as_ref()?.write_all(content.as_bytes()).ok()?;
    let result = output.wait_with_output().ok()?;

    // Parse macOS time output
    let stderr = String::from_utf8_lossy(&result.stderr);
    parse_macos_time_output(&stderr)
}

#[cfg(not(target_os = "macos"))]
fn measure_memory(content: &str) -> Option<MemoryUsage> {
    // Fallback: just run and return None for memory stats
    let mut child = Command::new(get_pipeguard_binary())
        .arg("scan")
        .arg("--rules")
        .arg(get_rules_path())
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

    child.stdin.take()?.write_all(content.as_bytes()).ok()?;
    child.wait().ok()?;
    None
}

/// Parse macOS /usr/bin/time -l output
fn parse_macos_time_output(output: &str) -> Option<MemoryUsage> {
    let mut peak_memory_bytes = 0u64;
    let mut page_faults = 0u64;

    for line in output.lines() {
        let line = line.trim();
        if line.contains("maximum resident set size") || line.contains("peak memory footprint") {
            if let Some(num) = line.split_whitespace().next() {
                peak_memory_bytes = num.parse().unwrap_or(0);
            }
        }
        if line.contains("page faults") {
            if let Some(num) = line.split_whitespace().next() {
                page_faults = num.parse().unwrap_or(0);
            }
        }
    }

    if peak_memory_bytes > 0 {
        Some(MemoryUsage {
            peak_bytes: peak_memory_bytes,
            page_faults,
        })
    } else {
        None
    }
}

#[derive(Debug, Clone)]
pub struct MemoryUsage {
    pub peak_bytes: u64,
    pub page_faults: u64,
}

impl MemoryUsage {
    pub fn peak_mb(&self) -> f64 {
        self.peak_bytes as f64 / (1024.0 * 1024.0)
    }
}

#[derive(Debug)]
pub struct MemoryResult {
    pub input_size: usize,
    pub usage: Option<MemoryUsage>,
}

#[derive(Debug)]
pub struct MemoryReport {
    pub results: Vec<MemoryResult>,
    pub iterations: usize,
}

impl std::fmt::Display for MemoryReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Memory Usage Report ({} iterations) ===", self.iterations)?;
        writeln!(f)?;
        writeln!(f, "{:>12} | {:>12} | {:>12}",
                 "Input Size", "Peak Memory", "Page Faults")?;
        writeln!(f, "{:-<12}-+-{:-<12}-+-{:-<12}", "", "", "")?;

        for r in &self.results {
            if let Some(ref usage) = r.usage {
                writeln!(f, "{:>12} | {:>10.2} MB | {:>12}",
                         format_size(r.input_size),
                         usage.peak_mb(),
                         usage.page_faults)?;
            } else {
                writeln!(f, "{:>12} | {:>12} | {:>12}",
                         format_size(r.input_size),
                         "N/A", "N/A")?;
            }
        }

        // Memory efficiency analysis
        if let (Some(first), Some(last)) = (
            self.results.first().and_then(|r| r.usage.as_ref()),
            self.results.last().and_then(|r| r.usage.as_ref()),
        ) {
            let input_growth = self.results.last().unwrap().input_size as f64
                / self.results.first().unwrap().input_size as f64;
            let memory_growth = last.peak_bytes as f64 / first.peak_bytes as f64;

            writeln!(f)?;
            writeln!(f, "Memory Efficiency:")?;
            writeln!(f, "  Input growth: {:.0}x", input_growth)?;
            writeln!(f, "  Memory growth: {:.2}x", memory_growth)?;
            writeln!(f, "  Ratio: {:.2}x (lower is better)", memory_growth / input_growth)?;
        }

        Ok(())
    }
}

fn format_size(bytes: usize) -> String {
    if bytes >= 1_000_000 {
        format!("{:.1} MB", bytes as f64 / 1_000_000.0)
    } else if bytes >= 1_000 {
        format!("{:.1} KB", bytes as f64 / 1_000.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Run memory analysis across different input sizes
pub fn memory_analysis(iterations: usize) -> MemoryReport {
    let mut results = Vec::new();

    for &size in SAMPLE_SIZES {
        let payload = generate_payload(size);

        // Average multiple measurements
        let mut measurements: Vec<MemoryUsage> = Vec::new();
        for _ in 0..iterations {
            if let Some(usage) = measure_memory(&payload) {
                measurements.push(usage);
            }
        }

        let avg_usage = if !measurements.is_empty() {
            Some(MemoryUsage {
                peak_bytes: measurements.iter().map(|m| m.peak_bytes).sum::<u64>()
                    / measurements.len() as u64,
                page_faults: measurements.iter().map(|m| m.page_faults).sum::<u64>()
                    / measurements.len() as u64,
            })
        } else {
            None
        };

        results.push(MemoryResult {
            input_size: size,
            usage: avg_usage,
        });
    }

    MemoryReport { results, iterations }
}

fn memory_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory");
    group.measurement_time(Duration::from_secs(5));
    group.sample_size(20);

    for &size in SAMPLE_SIZES {
        let payload = generate_payload(size);

        group.bench_with_input(
            BenchmarkId::new("scan", format_size(size)),
            &payload,
            |b, content| {
                b.iter(|| {
                    let mut child = Command::new(get_pipeguard_binary())
                        .arg("scan")
                        .arg("--rules")
                        .arg(get_rules_path())
                        .stdin(Stdio::piped())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn()
                        .expect("spawn");
                    child.stdin.take().unwrap().write_all(content.as_bytes()).ok();
                    child.wait()
                })
            },
        );
    }

    group.finish();
}

criterion_group!(benches, memory_benchmark);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_report() {
        let report = memory_analysis(3);
        println!("{}", report);

        // Basic sanity check - memory should be bounded
        for r in &report.results {
            if let Some(ref usage) = r.usage {
                // Peak memory should be under 100MB for reasonable inputs
                if r.input_size <= 100_000 {
                    assert!(
                        usage.peak_mb() < 100.0,
                        "Peak memory too high for size {}: {:.2} MB",
                        r.input_size, usage.peak_mb()
                    );
                }
            }
        }
    }

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(500), "500 B");
        assert_eq!(format_size(1500), "1.5 KB");
        assert_eq!(format_size(1_500_000), "1.5 MB");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_parse_macos_output() {
        let sample = r#"
        0.01 real         0.00 user         0.00 sys
            2138112  maximum resident set size
                  0  average shared memory size
                  0  average unshared data size
                  0  average unshared stack size
                523  page reclaims
                  0  page faults
        "#;

        let usage = parse_macos_time_output(sample).unwrap();
        assert_eq!(usage.peak_bytes, 2138112);
    }
}
