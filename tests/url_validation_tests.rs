// Tests for update source URL validation
// Covers: HTTPS enforcement, GitHub host whitelist, path structure, SSRF prevention

use pipeguard::update::UpdateConfig;

// ─── Valid URLs ─────────────────────────────────────────────────

#[test]
fn valid_github_https_url() {
    let config = UpdateConfig {
        source: "https://github.com/SecurityRonin/pipeguard".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_ok());
}

#[test]
fn valid_github_url_with_trailing_slash() {
    let config = UpdateConfig {
        source: "https://github.com/SecurityRonin/pipeguard/".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_ok());
}

#[test]
fn valid_github_url_case_insensitive_host() {
    let config = UpdateConfig {
        source: "https://GitHub.com/owner/repo".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_ok());
}

// ─── Rejected: non-HTTPS ────────────────────────────────────────

#[test]
fn reject_http_url() {
    let config = UpdateConfig {
        source: "http://github.com/owner/repo".to_string(),
        ..Default::default()
    };
    let err = config.validate_source_url().unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("HTTPS"), "Should mention HTTPS: {}", msg);
}

#[test]
fn reject_ftp_url() {
    let config = UpdateConfig {
        source: "ftp://github.com/owner/repo".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

// ─── Rejected: non-GitHub hosts (SSRF prevention) ───────────────

#[test]
fn reject_non_github_host() {
    let config = UpdateConfig {
        source: "https://evil.com/owner/repo".to_string(),
        ..Default::default()
    };
    let err = config.validate_source_url().unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("github.com"),
        "Should mention allowed host: {}",
        msg
    );
}

#[test]
fn reject_github_lookalike() {
    let config = UpdateConfig {
        source: "https://github.com.evil.com/owner/repo".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

#[test]
fn reject_internal_ip_ssrf() {
    let urls = vec![
        "https://127.0.0.1/owner/repo",
        "https://localhost/owner/repo",
        "https://192.168.1.1/owner/repo",
        "https://10.0.0.1/owner/repo",
        "https://[::1]/owner/repo",
    ];
    for url in urls {
        let config = UpdateConfig {
            source: url.to_string(),
            ..Default::default()
        };
        assert!(
            config.validate_source_url().is_err(),
            "Should reject SSRF attempt: {}",
            url
        );
    }
}

// ─── Rejected: malformed URLs ───────────────────────────────────

#[test]
fn reject_empty_source() {
    let config = UpdateConfig {
        source: String::new(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

#[test]
fn reject_not_a_url() {
    let config = UpdateConfig {
        source: "not a url at all".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

#[test]
fn reject_missing_repo_path() {
    let config = UpdateConfig {
        source: "https://github.com/".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

#[test]
fn reject_owner_only_no_repo() {
    let config = UpdateConfig {
        source: "https://github.com/owner".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

// ─── Rejected: path traversal in URL ────────────────────────────

#[test]
fn reject_path_traversal_in_url() {
    let config = UpdateConfig {
        source: "https://github.com/../../../etc/passwd".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}

#[test]
fn reject_url_with_credentials() {
    let config = UpdateConfig {
        source: "https://user:pass@github.com/owner/repo".to_string(),
        ..Default::default()
    };
    assert!(config.validate_source_url().is_err());
}
