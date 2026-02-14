use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pipeguard::detection::pipeline::{DetectionPipeline, PipelineConfig};

fn generate_rules(count: usize) -> String {
    (0..count)
        .map(|i| {
            format!(
                r#"
rule test_rule_{i} {{
    meta:
        severity = 5
        description = "Test rule {i}"
    strings:
        $s = "malicious_pattern_{i}"
    condition:
        any of them
}}
"#
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn pipeline_creation(c: &mut Criterion) {
    for count in [1, 5, 10, 25] {
        let rules = generate_rules(count);
        c.bench_function(&format!("create_pipeline_{count}_rules"), |b| {
            b.iter(|| DetectionPipeline::new(black_box(&rules), PipelineConfig::default()))
        });
    }
}

criterion_group!(benches, pipeline_creation);
criterion_main!(benches);
