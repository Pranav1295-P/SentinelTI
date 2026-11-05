// SentinelTI starter rules. These describe generic techniques, not malware families.
// Add your own .yar files to this folder. Meta fields the platform reads:
//   score     how much a hit adds to the risk score
//   family    malware family to attribute when the rule hits
//   technique MITRE ATT&CK id

rule Packer_UPX
{
    meta:
        description = "UPX packer stub or section names"
        score = 10
        technique = "T1027.002"
    strings:
        $a = "UPX!" ascii
        $b = "UPX0" ascii
        $c = "UPX1" ascii
    condition:
        uint16(0) == 0x5A4D and 2 of them
}

rule Injection_API_Chain
{
    meta:
        description = "Remote process injection API chain"
        score = 10
        technique = "T1055"
    strings:
        $alloc = "VirtualAllocEx" ascii wide
        $write = "WriteProcessMemory" ascii wide
        $thread1 = "CreateRemoteThread" ascii wide
        $thread2 = "NtCreateThreadEx" ascii wide
        $thread3 = "QueueUserAPC" ascii wide
    condition:
        $alloc and $write and any of ($thread*)
}

rule Run_Key_Persistence
{
    meta:
        description = "Registry Run key path together with a registry write API"
        score = 8
        technique = "T1547.001"
    strings:
        $path = "CurrentVersion\\Run" ascii wide nocase
        $api1 = "RegSetValueEx" ascii wide
        $api2 = "RegCreateKey" ascii wide
    condition:
        $path and any of ($api*)
}

rule Shadow_Copy_Deletion
{
    meta:
        description = "Commands that destroy Volume Shadow Copies"
        score = 25
        technique = "T1490"
    strings:
        $a = "vssadmin delete shadows" ascii wide nocase
        $b = "wmic shadowcopy delete" ascii wide nocase
        $c = "bcdedit /set {default} recoveryenabled no" ascii wide nocase
    condition:
        any of them
}

rule Encoded_PowerShell
{
    meta:
        description = "PowerShell launched with an encoded or hidden command"
        score = 15
        technique = "T1059.001"
    strings:
        $ps = "powershell" ascii wide nocase
        $enc1 = "-enc" ascii wide nocase
        $enc2 = "-encodedcommand" ascii wide nocase
        $hidden = "-w hidden" ascii wide nocase
    condition:
        $ps and any of ($enc*, $hidden)
}

rule LSASS_Memory_Access
{
    meta:
        description = "LSASS targeted together with a memory dump API"
        score = 20
        technique = "T1003.001"
    strings:
        $target = "lsass.exe" ascii wide nocase
        $dump = "MiniDumpWriteDump" ascii wide
    condition:
        $target and $dump
}

rule Ransom_Note_Language
{
    meta:
        description = "Phrases typical of a ransom note"
        score = 20
        technique = "T1486"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "decrypt your files" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = "pay the ransom" ascii wide nocase
    condition:
        2 of them
}

rule EICAR_Test_File
{
    meta:
        description = "EICAR antivirus test string (harmless)"
        family = "EICAR Test File"
        score = 40
    strings:
        $a = "EICAR-STANDARD-ANTIVIRUS-TEST-FILE" ascii
    condition:
        $a
}
