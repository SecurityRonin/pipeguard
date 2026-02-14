/*
 * PipeGuard YARA Rules — Anti-Analysis
 * Severity: 5-6
 * Rules: 3
 */

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
