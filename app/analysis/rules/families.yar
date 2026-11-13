// Family rules. A hit attributes the family, using strings these tools are publicly known to contain.

rule Remcos_RAT
{
    meta:
        description = "Strings specific to the Remcos remote access trojan"
        family = "Remcos RAT"
        score = 60
        technique = "T1219"
    strings:
        $a = "Remcos_Mutex_Inj" ascii wide
        $b = "Breaking-Security.Net" ascii wide nocase
        $c = "licence_code.txt" ascii wide
        $d = "Initializing connection to C&C" ascii wide
        $e = "Uploading file to C&C" ascii wide
        $f = "Offline Keylogger Started" ascii wide
        $g = "Online Keylogger Started" ascii wide
        $h = "Remcos v" ascii wide
    condition:
        2 of them
}
