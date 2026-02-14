/*
 * PipeGuard YARA Rules — Python Supply Chain Attacks
 * Severity: 7-10
 * Rules: 10
 */

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
        $aria2c = "aria2c" nocase
        $axel = "axel" nocase
        $bash = /bash|sh/
    condition:
        ($subprocess and $shell) or ($system and ($curl or $wget or $aria2c or $axel or $bash))
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
        $exec and ($urllib or $urlopen or $requests) and $http
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
        $urllib and $http and ($chmod or $stat) and ($system or $popen)
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
        $exec and ($urllib or $urlopen) and $read and $http
}

rule python_nohup_background {
    meta:
        severity = 7
        description = "Python silent background execution"
        category = "supply_chain"
    strings:
        $nohup = "nohup"
        $background = "& "
        $devnull = "/dev/null"
        $system = "os.system"
        $curl = "curl" nocase
        $wget = "wget" nocase
        $aria2c = "aria2c" nocase
    condition:
        $nohup and $background and ($devnull or $system) and ($curl or $wget or $aria2c)
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
        $wget = "wget" nocase
        $aria2c = "aria2c" nocase
        $eval = "eval"
    condition:
        ($os_system or $subprocess) and ($backtick or $dollar_paren) and ($curl or $wget or $aria2c or $eval)
}
