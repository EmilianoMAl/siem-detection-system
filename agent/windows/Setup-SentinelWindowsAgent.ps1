# Instalador del agente Windows de SENTINEL. Automatiza lo que en la
# práctica se hizo a mano una vez (y costó bastante depurar):
#   1. Activa las políticas de auditoría necesarias (logon, cuentas).
#   2. Escribe Ship-WindowsEvents.ps1 en C:\SENTINEL.
#   3. Registra una Tarea Programada que lo corre como SYSTEM al
#      arrancar la VM (no depende de una sesión de usuario abierta).
#   4. Manda un evento de prueba y confirma si SENTINEL lo recibió.
#
# Correr como Administrador:
#   .\Setup-SentinelWindowsAgent.ps1 -SentinelHost 163.192.142.214 -SentinelPort 5514

param(
    [string]$SentinelHost = "163.192.142.214",
    [int]$SentinelPort = 5514,
    [string]$InstallDir = "C:\SENTINEL"
)

$ErrorActionPreference = "Stop"

function Write-Step($msg) { Write-Host "`n==> $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "    OK: $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "    AVISO: $msg" -ForegroundColor Yellow }

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Este instalador necesita correr como Administrador. Ábrelo con 'Ejecutar como administrador'." -ForegroundColor Red
    exit 1
}

Write-Step "Activando auditoría de Windows (logon, cuentas, grupos privilegiados)"
# Nombres en inglés -- funcionan como alias aunque Windows esté en
# español (confirmado en la práctica: auditpol los reconoce igual).
$categories = @("Logon", "User Account Management", "Security Group Management")
foreach ($cat in $categories) {
    auditpol /set /subcategory:"$cat" /success:enable /failure:enable | Out-Null
    Write-Ok "$cat (success + failure)"
}

Write-Step "Instalando el shipper en $InstallDir"
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
$shipperSource = Join-Path $PSScriptRoot "Ship-WindowsEvents.ps1"
if (-not (Test-Path $shipperSource)) {
    Write-Host "No encuentro Ship-WindowsEvents.ps1 junto a este instalador -- deben ir en la misma carpeta." -ForegroundColor Red
    exit 1
}
Copy-Item $shipperSource -Destination (Join-Path $InstallDir "Ship-WindowsEvents.ps1") -Force
Write-Ok "Copiado a $InstallDir\Ship-WindowsEvents.ps1"

Write-Step "Registrando la Tarea Programada (corre como SYSTEM, arranca con la VM)"
$taskName = "SENTINEL Windows Shipper"
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue

$scriptPath = Join-Path $InstallDir "Ship-WindowsEvents.ps1"
$argumentList = "-ExecutionPolicy Bypass -WindowStyle Hidden -File `"$scriptPath`" -SentinelHost $SentinelHost -SentinelPort $SentinelPort"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $argumentList
$trigger = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
Start-ScheduledTask -TaskName $taskName
Start-Sleep -Seconds 2

$task = Get-ScheduledTask -TaskName $taskName
if ($task.State -eq "Running") {
    Write-Ok "Tarea '$taskName' corriendo"
} else {
    Write-Warn "La tarea existe pero su estado es '$($task.State)' -- revisa el Programador de tareas."
}

Write-Step "Enviando evento de prueba a $SentinelHost:$SentinelPort"
$udpClient = New-Object System.Net.Sockets.UdpClient
$invariant = [System.Globalization.CultureInfo]::InvariantCulture
$ts = (Get-Date).ToString("MMM dd HH:mm:ss", $invariant)
$testRecord = @{ EventID = 9999; Channel = "SetupTest"; Hostname = $env:COMPUTERNAME; Message = "Prueba de instalacion del agente Windows de SENTINEL" }
$json = $testRecord | ConvertTo-Json -Compress
$line = "<134>$ts $($env:COMPUTERNAME) sentinel_winlog: $json"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($line)
$udpClient.Send($bytes, $bytes.Length, $SentinelHost, $SentinelPort) | Out-Null
Write-Ok "Paquete de prueba enviado"

Write-Host "`nListo. Verifica en el dashboard de SENTINEL (Workspace 'VM real', Log Source 'WINDOWS') que aparezca" -ForegroundColor Cyan
Write-Host "un evento de $env:COMPUTERNAME con canal SetupTest -- si no aparece en ~10s, revisa conectividad de red" -ForegroundColor Cyan
Write-Host "hacia $($SentinelHost):$($SentinelPort)/udp (firewall/NAT de esta VM)." -ForegroundColor Cyan
