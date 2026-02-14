# Known Detection Gaps

These tests represent real-world malware patterns that PipeGuard's YARA rules do not yet detect. They are skipped in CI to keep the build green while tracking coverage gaps.

## Skipped Tests

### 1. `edge_case_download_exec_multiline`

- **File**: `tests/download_detection_tests.rs`
- **What it tests**: Multi-line download-then-execute (`aria2c ... && chmod +x && ./exploit`)
- **Why it fails**: YARA rules match single-line download-execute patterns but miss the same sequence split across lines
- **Fix approach**: Add a YARA rule with `\n` or `\s` wildcards, or pre-join lines before scanning

### 2. `real_npm_depconf_exfil`

- **File**: `tests/malware_detection_tests.rs`
- **What it tests**: npm dependency-confusion preinstall hook exfiltrating `$(whoami)` via webhook.site
- **Why it fails**: Rule doesn't match the JSON `"scripts": {"preinstall": ...}` wrapper around the `wget` exfiltration
- **Fix approach**: Add a YARA rule for npm/package.json preinstall/postinstall hooks containing `wget`/`curl` with command substitution

### 3. `real_shell_command_substitution`

- **File**: `tests/malware_detection_tests.rs`
- **What it tests**: `curl` with `$(whoami)`, `$(hostname)` command-substitution exfiltration
- **Why it fails**: Existing exfiltration rules require more specific patterns than bare `$(whoami)` in a URL
- **Fix approach**: Add a YARA rule matching `curl`/`wget` URLs containing `$(...)` or backtick substitution

### 4. `real_pythonw_hidden_execution`

- **File**: `tests/malware_detection_tests.rs`
- **What it tests**: Using `pythonw` (windowless) to run a dropped payload
- **Why it fails**: No YARA rule covers the `pythonw` evasion technique (replacing `.exe` suffix with `w.exe`)
- **Fix approach**: Add a YARA rule matching `pythonw` or the string-replace evasion pattern

### 5. `real_reverseshell_obfuscated_oneliner`

- **File**: `tests/malware_detection_tests.rs`
- **What it tests**: Obfuscated Python reverse shell using string evaluation with `subprocess.run(..., shell=True)`
- **Why it fails**: The string-wrapped invocation evades existing reverse shell rules that match literal patterns
- **Fix approach**: Add rules matching string evaluation combined with `subprocess` imports, or `shell=True` with network-related strings

### 6. `real_setuptools_custom_install`

- **File**: `tests/malware_detection_tests.rs`
- **What it tests**: Malicious setuptools `CustomInstallCommand` extending `install` (boogipop malware family)
- **Why it fails**: No rule matches the `setuptools.command.install` + custom command class pattern
- **Fix approach**: Add a YARA rule for Python files importing `setuptools.command.install` and defining a class that extends `install`

### 7. `real_reverseshell_tcp_client`

- **File**: `tests/malware_detection_tests.rs`
- **What it tests**: Python reverse shell using raw `socket.socket` with `subprocess.run(shell=True)`
- **Why it fails**: Existing Python reverse shell rules focus on `pty.spawn` and `/bin/sh` patterns, not raw socket + subprocess
- **Fix approach**: Add a rule matching `from socket import` combined with `subprocess.run` and `shell=True`

## Contributing

To close a detection gap:

1. Write a new YARA rule in `rules/core.yar`
2. Verify the corresponding test passes: `cargo test <test_name>`
3. Remove the `--skip <test_name>` from CI (`ci.yml`) and the Makefile
4. Remove the entry from this file
