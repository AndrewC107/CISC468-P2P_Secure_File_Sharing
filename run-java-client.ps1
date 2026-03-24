# Reload PATH from registry (fixes "mvn not recognized" in Cursor/VS Code terminals)
$env:Path =
    [Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
    [Environment]::GetEnvironmentVariable("Path", "User")

$mvn = $null
if (Get-Command mvn -ErrorAction SilentlyContinue) {
    $mvn = "mvn"
} elseif (Test-Path "C:\Apache\maven\apache-maven-3.9.14\bin\mvn.cmd") {
    $mvn = "C:\Apache\maven\apache-maven-3.9.14\bin\mvn.cmd"
}

if (-not $mvn) {
    Write-Error "mvn not found. Add Maven's bin folder to your user PATH, or set MAVEN_HOME and try again."
    exit 1
}

Set-Location $PSScriptRoot
& $mvn -f java-client exec:java @args
