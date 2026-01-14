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

// =============================================================================
// Category 11: Python Supply Chain Attacks (Severity: 7-9)
// Source: DataDog GuardDog patterns
// =============================================================================

rule python_subprocess_shell_injection {
    meta:
        severity = 8
        description = "Python subprocess with shell injection"
        category = "supply_chain"
    strings:
        $subprocess = "subprocess.Popen" nocase
        $system = "os.system" nocase
        $shell = "shell=True"
        $curl = "curl" nocase
        $wget = "wget" nocase
        $bash = /bash|sh/
    condition:
        ($subprocess and $shell) or ($system and ($curl or $wget or $bash))
}

rule python_exec_base64 {
    meta:
        severity = 8
        description = "Python exec with base64 obfuscation"
        category = "supply_chain"
    strings:
        $exec = /exec|eval/
        $b64_module = "base64" nocase
        $b64decode = "b64decode"
        $import = "__import__"
    condition:
        $exec and ($b64decode or ($b64_module and $import))
}

rule python_exec_remote {
    meta:
        severity = 9
        description = "Python exec/eval with remote code"
        category = "supply_chain"
    strings:
        $exec = /exec|eval/
        $urllib = "urllib" nocase
        $urlopen = "urlopen"
        $requests = "requests" nocase
        $http = /https?:\/\//
    condition:
        $exec and ($urlopen or $requests) and $http
}

rule python_env_exfiltration {
    meta:
        severity = 8
        description = "Python environment variable exfiltration"
        category = "supply_chain"
    strings:
        $os_environ = "os.environ"
        $getenv = "os.getenv"
        $aws_key = "AWS_ACCESS_KEY_ID" nocase
        $aws_secret = "AWS_SECRET_ACCESS_KEY" nocase
        $post = /requests\.post|urllib.*urlopen/
        $http = /https?:\/\//
    condition:
        ($os_environ or ($getenv and ($aws_key or $aws_secret))) and $post and $http
}

rule python_ssh_key_exfil {
    meta:
        severity = 9
        description = "Python SSH key exfiltration"
        category = "supply_chain"
    strings:
        $ssh_key = ".ssh/id_rsa"
        $ssh_dir = ".ssh/"
        $socket = "socket.socket"
        $open_read = "open("
        $send = /\.send|\.sendall/
    condition:
        ($ssh_key or $ssh_dir) and $socket and $open_read and $send
}

rule python_download_execute {
    meta:
        severity = 8
        description = "Python download and execute binary"
        category = "supply_chain"
    strings:
        $urllib = "urllib.request.urlretrieve"
        $chmod = "os.chmod"
        $stat = "stat.S_IXUSR"
        $system = "os.system"
        $popen = "subprocess.Popen"
        $http = /https?:\/\//
    condition:
        $urllib and $http and $chmod and ($system or $popen)
}

rule python_fileless_execution {
    meta:
        severity = 9
        description = "Python fileless (memory-only) execution"
        category = "supply_chain"
    strings:
        $exec = /exec|eval/
        $urllib = "urllib" nocase
        $urlopen = "urlopen"
        $read = ".read()"
        $http = /https?:\/\//
    condition:
        $exec and $urlopen and $read and $http
}

rule python_nohup_background {
    meta:
        severity = 7
        description = "Python silent background execution"
        category = "supply_chain"
    strings:
        $nohup = "nohup"
        $background = "&"
        $devnull = "/dev/null"
        $system = "os.system"
        $curl = "curl" nocase
    condition:
        $nohup and $background and ($devnull or $system) and $curl
}

// =============================================================================
// Category 12: Node.js/npm Supply Chain Attacks (Severity: 7-8)
// =============================================================================

rule npm_malicious_install_script {
    meta:
        severity = 8
        description = "npm install script with malicious command"
        category = "supply_chain"
    strings:
        $scripts = "\"scripts\""
        $postinstall = "postinstall" nocase
        $preinstall = "preinstall" nocase
        $curl = "curl" nocase
        $wget = "wget" nocase
        $bash = /\|\s*bash/
        $sh = /\|\s*sh/
    condition:
        $scripts and ($postinstall or $preinstall) and ($curl or $wget) and ($bash or $sh)
}

rule npm_node_exec_injection {
    meta:
        severity = 8
        description = "npm node -e with command injection"
        category = "supply_chain"
    strings:
        $node_e = /node\s+-e/
        $child_process = "child_process"
        $exec = ".exec"
        $curl = "curl" nocase
        $eval = "eval"
    condition:
        $node_e and ($child_process and $exec) or ($node_e and $curl and $eval)
}

// =============================================================================
// Category 13: Real-World Attack Patterns (Severity: 9-10)
// =============================================================================

rule python_setuptools_custom_install {
    meta:
        severity = 9
        description = "Suspicious setuptools custom install command"
        category = "supply_chain"
    strings:
        $setuptools = "setuptools.command.install"
        $custom_class = "class CustomInstallCommand"
        $os_system = "os.system"
        $subprocess = "subprocess"
        $bash_i = "bash -i"
        $dev_tcp = "/dev/tcp/"
    condition:
        $setuptools and $custom_class and ($os_system or $subprocess) and ($bash_i or $dev_tcp)
}

rule python_tempfile_exec_hidden {
    meta:
        severity = 8
        description = "Temporary file with hidden execution (pythonw pattern)"
        category = "supply_chain"
    strings:
        $tempfile = "tempfile" nocase
        $namedtemp = "NamedTemporaryFile"
        $exec = /exec|eval/
        $urlopen = "urlopen"
        $pythonw = "pythonw"
        $sys_exec = "sys.executable"
    condition:
        ($tempfile or $namedtemp) and $exec and ($urlopen or $pythonw or $sys_exec)
}

rule python_obfuscated_imports {
    meta:
        severity = 7
        description = "Obfuscated Python imports"
        category = "supply_chain"
    strings:
        $__import__ = "__import__"
        $chr = "chr("
        $ord = "ord("
        $join = "join("
        $exec = /exec|eval/
    condition:
        $__import__ and ($chr or $ord) and $join and $exec
}

rule python_pastebin_c2 {
    meta:
        severity = 9
        description = "Pastebin used as C2 channel"
        category = "supply_chain"
    strings:
        $pastebin = /paste\.bingner\.com|pastebin\.com|paste\.ee/
        $raw = "/raw/"
        $exec = /exec|eval/
        $urllib = "urllib" nocase
    condition:
        $pastebin and ($raw or $exec) and $urllib
}

rule python_reverseshell_obfuscated {
    meta:
        severity = 10
        description = "Obfuscated Python reverse shell"
        category = "supply_chain"
    strings:
        $socket = "socket.socket"
        $connect = ".connect"
        $subprocess = "subprocess"
        $popen = "Popen"
        $stdin = "stdin"
        $stdout = "stdout"
        $base64 = "base64"
        $b64decode = "b64decode"
    condition:
        $socket and $connect and ($subprocess or $popen) and ($stdin or $stdout) and ($base64 or $b64decode)
}

rule python_shell_command_substitution {
    meta:
        severity = 8
        description = "Shell command substitution in Python"
        category = "supply_chain"
    strings:
        $os_system = "os.system"
        $subprocess = "subprocess"
        $backtick = "`"
        $dollar_paren = "$("
        $curl = "curl" nocase
        $eval = "eval"
    condition:
        ($os_system or $subprocess) and ($backtick or $dollar_paren) and ($curl or $eval)
}
