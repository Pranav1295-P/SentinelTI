"""Capability detection: correlates APIs, strings and section anomalies.

A capability is "proven" only when its whole evidence chain is present. A partial
chain is reported as unproven and adds nothing to the risk score.
"""

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    weight: int
    techniques: tuple[str, ...]
    explanation: str
    # Every group must have at least one API present.
    apis: tuple[tuple[str, ...], ...] = ()
    # At least one pattern must match when any are listed.
    strings: tuple[str, ...] = ()


RULES: tuple[Rule, ...] = (
    Rule("process_injection", "Process Injection", 30, ("T1055",),
         "Allocates and writes memory in another process, then starts a thread in it.",
         apis=(("VirtualAllocEx", "NtAllocateVirtualMemory", "ZwAllocateVirtualMemory"),
               ("WriteProcessMemory", "NtWriteVirtualMemory", "ZwWriteVirtualMemory"),
               ("CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx", "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread"))),
    Rule("process_hollowing", "Process Hollowing", 35, ("T1055.012",),
         "Unmaps a process image and replaces it with its own code.",
         apis=(("CreateProcess", "CreateProcessInternal"),
               ("NtUnmapViewOfSection", "ZwUnmapViewOfSection"),
               ("WriteProcessMemory", "NtWriteVirtualMemory"),
               ("SetThreadContext", "NtSetContextThread"))),
    Rule("run_key_persistence", "Registry Run-key Persistence", 18, ("T1547.001",),
         "Writes a Run key so it restarts at every logon.",
         apis=(("RegSetValueEx", "RegCreateKeyEx", "RegCreateKey", "NtSetValueKey", "SHSetValue"),),
         strings=(r"CurrentVersion\\Run(Once)?\b",)),
    Rule("service_persistence", "Windows Service Persistence", 15, ("T1543.003",),
         "Registers itself as a Windows service.",
         apis=(("OpenSCManager",), ("CreateService",))),
    Rule("scheduled_task", "Scheduled Task Persistence", 15, ("T1053.005",),
         "Creates a scheduled task.",
         strings=(r"schtasks(\.exe)?\s+/create",)),
    Rule("cron_persistence", "Cron Persistence", 15, ("T1053.003",),
         "Writes itself into a crontab.",
         strings=(r"/etc/cron\.|crontab\s+-",)),
    Rule("keylogging", "Keylogging", 25, ("T1056.001",),
         "Hooks or polls the keyboard state.",
         apis=(("SetWindowsHookEx", "GetAsyncKeyState", "GetKeyboardState"),
               ("GetForegroundWindow", "GetWindowText", "CallNextHookEx", "MapVirtualKey"))),
    Rule("screen_capture", "Screen Capture", 10, ("T1113",),
         "Copies the screen into a bitmap.",
         apis=(("BitBlt",), ("GetDC", "GetDesktopWindow", "GetWindowDC"), ("CreateCompatibleBitmap",))),
    Rule("lsass_dump", "LSASS Credential Dumping", 35, ("T1003.001",),
         "Targets LSASS memory, where Windows keeps credentials.",
         apis=(("MiniDumpWriteDump", "OpenProcess", "ReadProcessMemory"),),
         strings=(r"\blsass(\.exe)?\b",)),
    Rule("http_c2", "HTTP Communication", 5, ("T1071.001",),
         "Can make HTTP requests.",
         apis=(("InternetOpen", "WinHttpOpen", "HttpOpenRequest", "WinHttpConnect"),
               ("HttpSendRequest", "WinHttpSendRequest", "InternetConnect", "InternetOpenUrl"))),
    Rule("raw_socket", "Raw Socket Communication", 4, ("T1095",),
         "Opens raw network sockets.",
         apis=(("WSAStartup", "socket", "WSASocket"), ("connect", "WSAConnect"), ("send", "WSASend"))),
    Rule("downloader", "Downloads and Runs Payloads", 15, ("T1105",),
         "Downloads files from the internet to disk.",
         apis=(("URLDownloadToFile", "URLDownloadToCacheFile", "BITSAdmin"),)),
    Rule("ransomware_impact", "File Encryption for Impact", 30, ("T1486",),
         "Walks the file system and encrypts files, with a ransom message.",
         apis=(("CryptEncrypt", "BCryptEncrypt"), ("FindFirstFile", "FindNextFile")),
         strings=(r"files (have been|are|were) encrypted|decrypt your files|ransom",)),
    Rule("recovery_inhibit", "Destroys Recovery Options", 35, ("T1490",),
         "Deletes shadow copies or disables recovery.",
         strings=(r"vssadmin(\.exe)?\s+delete\s+shadows|wmic\s+shadowcopy\s+delete|recoveryenabled\s+no",)),
    Rule("encoded_powershell", "Encoded PowerShell", 20, ("T1059.001",),
         "Launches PowerShell with an encoded or hidden command.",
         strings=(r"powershell(\.exe)?\b.*\s-(e|ec|enc|encodedcommand|w\s+hidden|windowstyle\s+hidden)\b",)),
    Rule("command_shell", "Command Shell Execution", 3, ("T1059.003",),
         "Runs commands through cmd.exe.",
         strings=(r"cmd(\.exe)?\s+/[ck]\b",)),
    Rule("token_manipulation", "Token Privilege Manipulation", 8, ("T1134",),
         "Adjusts its access token privileges.",
         apis=(("OpenProcessToken",), ("AdjustTokenPrivileges",), ("LookupPrivilegeValue",))),
    Rule("anti_debug", "Debugger Detection", 4, ("T1622",),
         "Checks whether a debugger is attached.",
         apis=(("CheckRemoteDebuggerPresent", "NtQueryInformationProcess", "IsDebuggerPresent", "OutputDebugString"),)),
    Rule("dynamic_api", "Dynamic API Resolution", 2, ("T1027.007",),
         "Resolves APIs at runtime, so they are missing from the import table.",
         apis=(("LoadLibrary", "LdrLoadDll"), ("GetProcAddress", "LdrGetProcedureAddress"))),
    Rule("ptrace_injection", "Ptrace Injection", 20, ("T1055.008",),
         "Writes into another Linux process with ptrace.",
         apis=(("ptrace",),), strings=(r"/proc/\d*/?mem|PTRACE_POKE",)),
    Rule("preload_hijack", "Dynamic Linker Hijacking", 25, ("T1574.006",),
         "Abuses ld.so.preload or LD_PRELOAD.",
         strings=(r"/etc/ld\.so\.preload|LD_PRELOAD=",)),
)

# Text aimed at an LLM analyst rather than at a victim machine.
PROMPT_INJECTION = re.compile(
    r"ignore (all |any )?(the )?(previous|prior|above) (instructions|prompts?)"
    r"|disregard (all |any )?(the )?(previous|prior|above)"
    r"|(you are|act as) (now )?(an? )?(ai|assistant|llm|analyst)\b"
    r"|(mark|classify|report) (this|the) (file|sample|binary)( as)? (clean|safe|benign)"
    r"|system prompt",
    re.I,
)


def all_imports(parsed: dict) -> list[str]:
    return [name for names in parsed.get("imports", {}).values() for name in names]


def _api_matches(candidate: str, known: str) -> bool:
    """Compare ignoring case and the A/W suffix Windows puts on string APIs."""
    candidate = candidate.lower()
    known = known.lower()
    return candidate == known or candidate in (known + "a", known + "w", known + "exa", known + "exw")


def _find_api(group: tuple[str, ...], imports: list[str], tokens: set[str]) -> tuple[str, str] | None:
    for known in group:
        for name in imports:
            if _api_matches(name, known):
                return name, "import"
    for known in group:
        for suffix in ("", "A", "W", "ExA", "ExW"):
            if (known + suffix) in tokens:
                return known + suffix, "string"
    return None


def tokenize(strings: list[str]) -> set[str]:
    tokens: set[str] = set()
    for text in strings:
        if len(text) <= 256:
            tokens.update(re.findall(r"[A-Za-z_][A-Za-z0-9_]{3,63}", text))
    return tokens


def correlate(parsed: dict, strings: list[str]) -> list[dict]:
    """Return matched rules with the concrete API and string hits behind each."""
    imports = all_imports(parsed)
    tokens = tokenize(strings)
    results = []

    for rule in RULES:
        hits, missing = [], 0
        import_only = True
        for group in rule.apis:
            found = _find_api(group, imports, tokens)
            if found:
                hits.append({"type": "api", "value": found[0], "source": found[1]})
                import_only = import_only and found[1] == "import"
            else:
                missing += 1

        string_hit = None
        for pattern in rule.strings:
            regex = re.compile(pattern, re.I)
            string_hit = next((s for s in strings if len(s) <= 2048 and regex.search(s)), None)
            if string_hit:
                hits.append({"type": "string", "value": string_hit[:256]})
                break
        if rule.strings and not string_hit:
            missing += 1

        total = len(rule.apis) + (1 if rule.strings else 0)
        if not hits:
            continue

        if missing == 0:
            confidence = 0.95 if import_only and rule.apis else 0.8
            status = "proven"
        elif total >= 3 and missing == 1:
            confidence = 0.4
            status = "partial"
        else:
            continue

        results.append({
            "rule": rule, "status": status, "confidence": confidence, "hits": hits,
        })
    return results


def find_prompt_injection(strings: list[str]) -> list[str]:
    return [s[:256] for s in strings if PROMPT_INJECTION.search(s)][:10]
