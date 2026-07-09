# Revierte lo que hace Setup-SentinelWindowsAgent.ps1: detiene y borra
# la Tarea Programada y el directorio de instalación. No revierte las
# políticas de auditoría (auditpol) -- son configuración general de
# Windows, no algo exclusivo de SENTINEL, se dejan como estén.

param(
    [string]$InstallDir = "C:\SENTINEL"
)

$taskName = "SENTINEL Windows Shipper"

Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
Write-Host "Tarea programada '$taskName' eliminada."

if (Test-Path $InstallDir) {
    Remove-Item -Path $InstallDir -Recurse -Force
    Write-Host "$InstallDir eliminado."
}
