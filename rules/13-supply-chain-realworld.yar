/*
 * PipeGuard YARA Rules — Real-World Attack Patterns
 * Severity: 7-9
 * Rules: 4
 */

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
