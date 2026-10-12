rule ClamGuard_Demo_PE
{
    meta:
        description = "ClamGuard.NET YARA integration demo"
    strings:
        $mz = { 4D 5A }
        $text = "This is a ClamGuard YARA demo" ascii nocase
        $wide = "ClamGuard" wide ascii nocase
    condition:
        $mz and (1 of ($text, $wide))
}
