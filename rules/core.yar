/*
 * PipeGuard Core YARA Rules
 * Detecting malicious patterns in curl|bash attacks
 *
 * Severity Levels:
 *   1-6: Low (Warn)
 *   7-8: Medium (Prompt)
 *   9-10: High (Block)
 */

// =============================================================================
// Category 1: Base64 Obfuscation (Severity: 5)
// =============================================================================

rule base64_decode_execute {
    meta:
        severity = 5
        description = "Base64 encoded payload with execution"
        category = "obfuscation"
    strings:
        $decode1 = "base64 -d" nocase
        $decode2 = "base64 --decode" nocase
        $decode3 = "openssl base64 -d" nocase
        $exec1 = "| bash"
        $exec2 = "| sh"
        $exec3 = "| zsh"
        $exec4 = "eval $("
        $exec5 = "eval \"$("
    condition:
        any of ($decode*) and any of ($exec*)
}

rule large_base64_blob {
    meta:
        severity = 5
        description = "Large Base64 encoded data block"
        category = "obfuscation"
    strings:
        $b64 = /[A-Za-z0-9+\/]{100,}={0,2}/
    condition:
        $b64
}

// =============================================================================
// Category 2: Staged Downloads (Severity: 7)
// =============================================================================

rule staged_download_curl {
    meta:
        severity = 7
        description = "Script downloads and executes additional payloads"
        category = "staged"
    strings:
        $curl1 = "curl" nocase
        $curl2 = "wget" nocase
        $curl3 = "fetch" nocase
        $pipe1 = "| bash"
        $pipe2 = "| sh"
        $pipe3 = "| zsh"
        $pipe4 = "| python"
        $pipe5 = "| perl"
    condition:
        any of ($curl*) and any of ($pipe*)
}

rule multi_stage_download {
    meta:
        severity = 8
        description = "Multiple download commands suggesting staged attack"
        category = "staged"
    strings:
        $dl = /curl|wget|fetch/ nocase
    condition:
        #dl >= 3
}

// =============================================================================
// Category 3: Reverse Shells (Severity: 10)
// =============================================================================

rule reverse_shell_bash {
    meta:
        severity = 10
        description = "Bash reverse shell pattern"
        category = "reverse_shell"
    strings:
        $bash_i = "bash -i"
        $dev_tcp = "/dev/tcp/"
    condition:
        $bash_i and $dev_tcp
}

rule reverse_shell_nc {
    meta:
        severity = 10
        description = "Netcat reverse shell pattern"
        category = "reverse_shell"
    strings:
        $nc1 = /nc\s+-[elp]/ nocase
        $nc2 = /netcat\s+-[elp]/ nocase
        $nc3 = /ncat\s+-[elp]/ nocase
        $shell = /\/bin\/(ba)?sh/
    condition:
        any of ($nc*) and $shell
}

rule reverse_shell_python {
    meta:
        severity = 10
        description = "Python reverse shell pattern"
        category = "reverse_shell"
    strings:
        $socket = "socket.socket"
        $connect = ".connect("
        $pty = "pty.spawn"
        $subprocess = "subprocess.call"
    condition:
        ($socket and $connect) or $pty or $subprocess
}

rule reverse_shell_perl {
    meta:
        severity = 10
        description = "Perl reverse shell pattern"
        category = "reverse_shell"
    strings:
        $perl_socket = "IO::Socket::INET"
        $perl_exec = "exec(\"/bin/"
    condition:
        $perl_socket or $perl_exec
}

// =============================================================================
// Category 4: Persistence Mechanisms (Severity: 8)
// =============================================================================

rule persistence_launchagent {
    meta:
        severity = 8
        description = "macOS LaunchAgent persistence"
        category = "persistence"
    strings:
        $la_path1 = "~/Library/LaunchAgents"
        $la_path2 = "/Library/LaunchAgents"
        $la_path3 = "LaunchAgents/"
        $plist = ".plist"
    condition:
        any of ($la_path*) and $plist
}

rule persistence_crontab {
    meta:
        severity = 8
        description = "Crontab persistence"
        category = "persistence"
    strings:
        // Match write operations: crontab file, crontab -e/-r, crontab - (stdin)
        // Excludes: crontab -l (list)
        $cron_write = /crontab\s+[^-l\s]|crontab\s+-[erw]|crontab\s+-\s*$/
        $cron_pipe = /\|\s*crontab\s*-?\s*$/
        $cron_etc = "/etc/crontab"
        $cron_spool = "/var/spool/cron"
    condition:
        any of them
}

rule persistence_bashrc {
    meta:
        severity = 7
        description = "Shell RC file modification"
        category = "persistence"
    strings:
        $rc1 = ".bashrc"
        $rc2 = ".zshrc"
        $rc3 = ".profile"
        $rc4 = ".bash_profile"
        $write = />>|echo.*>>/
    condition:
        any of ($rc*) and $write
}

rule persistence_login_hook {
    meta:
        severity = 8
        description = "macOS login hook persistence"
        category = "persistence"
    strings:
        $hook = "LoginHook"
        $defaults = "defaults write"
    condition:
        $hook or ($defaults and /loginwindow/)
}

// =============================================================================
// Category 5: Privilege Escalation (Severity: 7)
// =============================================================================

rule privesc_sudo_stdin {
    meta:
        severity = 7
        description = "Sudo password from stdin"
        category = "privilege_escalation"
    strings:
        $sudo_s = "sudo -S"
        $echo_sudo = /echo.*\|.*sudo/
    condition:
        any of them
}

rule privesc_osascript_admin {
    meta:
        severity = 7
        description = "AppleScript admin privilege request"
        category = "privilege_escalation"
    strings:
        $osascript = "osascript"
        $admin = "administrator privileges"
        $password = "with prompt"
    condition:
        $osascript and ($admin or $password)
}

rule privesc_dscl {
    meta:
        severity = 8
        description = "User account manipulation via dscl"
        category = "privilege_escalation"
    strings:
        $dscl = "dscl"
        $create = "create"
        $admin = "admin"
    condition:
        $dscl and $create and $admin
}

// =============================================================================
// Category 6: Crypto Wallet Targeting (Severity: 9)
// =============================================================================

rule crypto_wallet_theft {
    meta:
        severity = 9
        description = "Cryptocurrency wallet targeting"
        category = "crypto_theft"
    strings:
        $wallet1 = "wallet.dat" nocase
        $wallet2 = "keystore" nocase
        $wallet3 = "electrum" nocase
        $wallet4 = "exodus" nocase
        $wallet5 = "atomic" nocase
        $wallet6 = "metamask" nocase
        $wallet7 = "phantom" nocase
        $wallet8 = "solflare" nocase
        $seed = "seed" nocase
        $mnemonic = "mnemonic" nocase
    condition:
        any of ($wallet*) or ($seed and $mnemonic)
}

rule crypto_browser_extension {
    meta:
        severity = 9
        description = "Browser crypto extension targeting"
        category = "crypto_theft"
    strings:
        $ext_path = "Extensions"
        $chrome = "Google/Chrome"
        $brave = "BraveSoftware"
        $ext_id1 = "nkbihfbeogaeaoehlefnkodbefgpgknn"  // MetaMask
        $ext_id2 = "bfnaelmomeimhlpmgjnjophhpkkoljpa"  // Phantom
    condition:
        $ext_path and (any of ($chrome, $brave) or any of ($ext_id*))
}

// =============================================================================
// Category 7: Quarantine Bypass (Severity: 9)
// =============================================================================

rule quarantine_bypass_xattr {
    meta:
        severity = 9
        description = "Gatekeeper quarantine attribute removal"
        category = "quarantine_bypass"
    strings:
        $xattr = "xattr"
        $quarantine = "com.apple.quarantine"
        $delete = "-d"
        $recursive = "-r"
    condition:
        $xattr and $quarantine and ($delete or $recursive)
}

rule quarantine_bypass_spctl {
    meta:
        severity = 9
        description = "Gatekeeper disable via spctl"
        category = "quarantine_bypass"
    strings:
        $spctl = "spctl"
        $disable = "--master-disable"
        $add = "--add"
    condition:
        $spctl and ($disable or $add)
}

// =============================================================================
// Category 8: AMOS/ClickFix IOCs (Severity: 10)
// =============================================================================

rule amos_stealer_indicators {
    meta:
        severity = 10
        description = "AMOS Stealer indicators"
        category = "amos"
    strings:
        $amos1 = "Atomic macOS Stealer" nocase
        $amos2 = "atomicstealer" nocase
        $amos3 = /keychain.*dump/i
        $amos4 = "security find-generic-password"
        $amos5 = "security dump-keychain"
    condition:
        any of them
}

rule clickfix_indicators {
    meta:
        severity = 10
        description = "ClickFix campaign indicators"
        category = "clickfix"
    strings:
        $cf1 = "I'm not a robot" nocase
        $cf2 = "verify you are human" nocase
        $cf3 = "press and hold" nocase
        $cf4 = "Windows + R" nocase
        $copy_paste = /copy.*paste|paste.*terminal/i
    condition:
        any of ($cf*) or $copy_paste
}

// =============================================================================
// Category 9: Environment Harvesting (Severity: 6)
// =============================================================================

rule env_harvesting {
    meta:
        severity = 6
        description = "Environment variable harvesting"
        category = "recon"
    strings:
        $env1 = "printenv"
        $env2 = "$HOME"
        $env3 = "$USER"
        $env4 = "$PATH"
        $env5 = "env |"
        $send = /curl|wget|nc/
    condition:
        2 of ($env*) and $send
}

rule credential_harvesting {
    meta:
        severity = 8
        description = "Credential file access"
        category = "recon"
    strings:
        $aws = ".aws/credentials"
        $ssh = ".ssh/"
        $gpg = ".gnupg/"
        $npm = ".npmrc"
        $docker = ".docker/config.json"
        $kube = ".kube/config"
    condition:
        any of them
}

// =============================================================================
// Category 10: Anti-Analysis (Severity: 5)
// =============================================================================

rule anti_analysis_vm_detect {
    meta:
        severity = 5
        description = "Virtual machine detection"
        category = "anti_analysis"
    strings:
        $vm1 = "VMware"
        $vm2 = "VirtualBox"
        $vm3 = "Parallels"
        $vm4 = "QEMU"
        $check = "system_profiler"
    condition:
        $check and any of ($vm*)
}

rule anti_analysis_sandbox_detect {
    meta:
        severity = 5
        description = "Sandbox detection"
        category = "anti_analysis"
    strings:
        $sb1 = "sandbox-exec"
        $sb2 = "/Library/Sandboxes"
        $sleep = /sleep\s+[0-9]{3,}/  // Long sleep (100+ seconds)
    condition:
        any of ($sb*) or $sleep
}

rule anti_analysis_debugger {
    meta:
        severity = 6
        description = "Debugger detection"
        category = "anti_analysis"
    strings:
        $ptrace = "ptrace"
        $sysctl = "sysctl"
        $debug = "P_TRACED"
    condition:
        $ptrace or ($sysctl and $debug)
}
