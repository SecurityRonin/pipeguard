/*
 * PipeGuard YARA Rules — Reverse Shells
 * Severity: 10
 * Rules: 4
 */

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
