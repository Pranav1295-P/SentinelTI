"""Local catalogue of the ATT&CK techniques the capability rules can reach.

Agent 4 can only ever report ids in this table, so an LLM cannot invent one.
"""

TECHNIQUES: dict[str, tuple[str, str]] = {
    "T1003.001": ("OS Credential Dumping: LSASS Memory", "Credential Access"),
    "T1027": ("Obfuscated Files or Information", "Defense Evasion"),
    "T1027.002": ("Obfuscated Files or Information: Software Packing", "Defense Evasion"),
    "T1027.007": ("Obfuscated Files or Information: Dynamic API Resolution", "Defense Evasion"),
    "T1036.007": ("Masquerading: Double File Extension", "Defense Evasion"),
    "T1036.008": ("Masquerading: Masquerade File Type", "Defense Evasion"),
    "T1053.003": ("Scheduled Task/Job: Cron", "Persistence"),
    "T1053.005": ("Scheduled Task/Job: Scheduled Task", "Persistence"),
    "T1055": ("Process Injection", "Defense Evasion"),
    "T1055.008": ("Process Injection: Ptrace System Calls", "Defense Evasion"),
    "T1055.012": ("Process Injection: Process Hollowing", "Defense Evasion"),
    "T1056.001": ("Input Capture: Keylogging", "Collection"),
    "T1059.001": ("Command and Scripting Interpreter: PowerShell", "Execution"),
    "T1059.003": ("Command and Scripting Interpreter: Windows Command Shell", "Execution"),
    "T1071.001": ("Application Layer Protocol: Web Protocols", "Command and Control"),
    "T1095": ("Non-Application Layer Protocol", "Command and Control"),
    "T1105": ("Ingress Tool Transfer", "Command and Control"),
    "T1113": ("Screen Capture", "Collection"),
    "T1134": ("Access Token Manipulation", "Privilege Escalation"),
    "T1486": ("Data Encrypted for Impact", "Impact"),
    "T1490": ("Inhibit System Recovery", "Impact"),
    "T1543.003": ("Create or Modify System Process: Windows Service", "Persistence"),
    "T1547.001": ("Boot or Logon Autostart Execution: Registry Run Keys", "Persistence"),
    "T1574.006": ("Hijack Execution Flow: Dynamic Linker Hijacking", "Persistence"),
    "T1622": ("Debugger Evasion", "Defense Evasion"),
}
