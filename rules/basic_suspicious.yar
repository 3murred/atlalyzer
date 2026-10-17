
rule Suspicious_PowerShell_Download
{
    meta:
        description = "Detecta padrões de download em scripts PowerShell"
        severity = "medium"

    strings:
        $download1 = "DownloadString" nocase
        $download2 = "DownloadFile" nocase
        $encoded = "-EncodedCommand" nocase

    condition:
        1 of them
}

rule Suspicious_Script_Execution
{
    meta:
        description = "Detecta padrões associados à execução de scripts"
        severity = "medium"

    strings:
        $exec1 = "WScript.Shell" nocase
        $exec2 = "CreateObject" nocase
        $exec3 = "powershell.exe" nocase

    condition:
        2 of them
}
