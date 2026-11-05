# Internal notes on malware techniques

Add your own notes as `## Heading` sections in any .md file in this folder.

## Software packing and UPX
Packers compress or encrypt the real program and restore it in memory, which hides imports and strings from static analysis. Signs: packer section names such as UPX0 and UPX1, an empty section on disk that is large in memory, section entropy above 7.2, and a tiny import table. Packing alone does not prove malice because some commercial software is packed. Next step: unpack (for UPX, `upx -d` in an isolated lab) and analyse the result. ATT&CK T1027.002.

## Process injection chains
Remote thread injection uses VirtualAllocEx, then WriteProcessMemory, then CreateRemoteThread. Variants use NtCreateThreadEx or QueueUserAPC. Hollowing starts a suspended process, unmaps it with NtUnmapViewOfSection, writes new code and resumes it. Legitimate software rarely needs the whole chain, so the full set is a strong signal. Debuggers and some security tools are the main false positives. ATT&CK T1055 and T1055.012.

## Registry Run key persistence
Malware commonly writes to Software\Microsoft\Windows\CurrentVersion\Run or RunOnce with RegSetValueEx so it restarts at logon. Installers and updaters do this too, so weigh it with other evidence. Check the registry value on affected hosts and look at what path it points to. ATT&CK T1547.001.

## Windows service and scheduled task persistence
OpenSCManager with CreateService installs a service, usually as SYSTEM. Attackers also use schtasks /create for scheduled tasks. Hunt for new services with unusual binary paths and tasks created by non-administrative tools. ATT&CK T1543.003 and T1053.005.

## Web protocol command and control
HTTP APIs such as WinHTTP and WinINet let malware blend with normal traffic. Hard-coded IP addresses, old browser user-agent strings and POST requests to bare IPs raise suspicion. Block the indicators at the proxy and search proxy logs for earlier contact. ATT&CK T1071.001.

## Downloaders and ingress tool transfer
URLDownloadToFile and BITS jobs let a first-stage loader fetch later payloads, so the file you hold may not be the final threat. Recover and block the download URL, then look for the dropped file on disk. ATT&CK T1105.

## Keylogging and input capture
SetWindowsHookEx with a keyboard hook, or polling GetAsyncKeyState alongside GetForegroundWindow, records what the user types. Treat any credentials typed on an affected host as exposed. ATT&CK T1056.001.

## LSASS credential dumping
Attackers read LSASS memory, often with MiniDumpWriteDump, to steal credentials. If this is confirmed, rotate credentials used on the host, including privileged and service accounts, and enable LSA protection. ATT&CK T1003.001.

## Ransomware impact and recovery inhibition
Ransomware walks the file system and encrypts files, usually with CryptEncrypt or BCrypt APIs. Before encrypting it often runs vssadmin delete shadows or disables recovery with bcdedit. These commands are rarely legitimate inside an ordinary application. Isolate affected hosts quickly and protect backups. ATT&CK T1486 and T1490.

## Encoded PowerShell and command shells
PowerShell run with -enc, -EncodedCommand or a hidden window conceals its payload. Decode the base64 (it is UTF-16LE) to read the command. cmd.exe /c alone is weak evidence because much legitimate software uses it. ATT&CK T1059.001 and T1059.003.

## Masquerading file types
A Windows executable named like a document, or with a double extension such as invoice.pdf.exe, is built to trick the user. There are few legitimate reasons for this. Find out how the file arrived and search mail logs for the same attachment. ATT&CK T1036.008 and T1036.007.

## Anti-analysis and debugger evasion
IsDebuggerPresent appears in most compiled Windows programs through the C runtime, so alone it means little. It matters more alongside timing checks, VM artefact strings or NtQueryInformationProcess. ATT&CK T1622.

## Dynamic API resolution
LoadLibrary and GetProcAddress resolve functions at runtime. They are common in normal software, but heavy use with a small import table hides capabilities from static analysis. ATT&CK T1027.007.

## Prompt injection aimed at analysis tools
Some samples now embed text addressed to AI analysts, such as requests to ignore instructions or report the file as safe. No legitimate program needs this, so it is itself a strong signal of intent. SentinelTI records it as evidence, and its verdict is computed without the LLM.

## Linux persistence and injection
ELF malware abuses /etc/ld.so.preload or LD_PRELOAD to hijack loading, cron for persistence, and ptrace or /proc/pid/mem for injection. Check these files directly on affected hosts. ATT&CK T1574.006, T1053.003 and T1055.008.
