# Equivalente Windows de agent/ship_logs.py -- en vez de leer un archivo
# de log y mandarlo por HTTP a /ingest, lee el Event Log nativo de
# Windows (Security/System) vía Get-WinEvent y lo manda por UDP syslog
# al mismo receptor que ya usan los demás agentes reales
# (engine/syslog_listener.py), con el tag "sentinel_winlog:" que
# engine/parsers/windows_eventlog_parser.py ya sabe reconocer.
#
# No depende de NXLog -- se probó en producción y su módulo
# im_msvistalog falló de forma consistente con "EvtNext returned
# ERROR_INVALID_OPERATION" al combinar canales en una sola suscripción,
# un bug conocido de esa librería. Get-WinEvent usa otra vía de la
# misma API de Windows que no tiene ese problema.
#
# Corre en un loop infinito -- pensado para ejecutarse como Tarea
# Programada (ver Setup-SentinelWindowsAgent.ps1), no interactivamente.

param(
    [string]$SentinelHost = "163.192.142.214",
    [int]$SentinelPort = 5514,
    [int]$PollSeconds = 5
)

$hostname = $env:COMPUTERNAME
$udpClient = New-Object System.Net.Sockets.UdpClient
$invariant = [System.Globalization.CultureInfo]::InvariantCulture

# EventID por canal -- mismo subconjunto que reconoce
# engine/parsers/windows_eventlog_parser.py::EVENT_TYPE_BY_ID. Agregar
# uno aquí sin agregarlo allá lo deja visible en Events como
# "windows_event" genérico, sin regla de detección todavía.
$filters = @{
    "Security" = "4624,4625,4720,4726,4728,4732,4698"
    "System"   = "7045"
}

# Arranca desde el evento más reciente de cada canal -- no reenvía
# historial viejo cada vez que se reinicia el script/la tarea.
$lastRecordId = @{
    "Security" = (Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
    "System"   = (Get-WinEvent -LogName System -MaxEvents 1 -ErrorAction SilentlyContinue).RecordId
}
if (-not $lastRecordId["Security"]) { $lastRecordId["Security"] = 0 }
if (-not $lastRecordId["System"])   { $lastRecordId["System"] = 0 }

while ($true) {
    foreach ($channel in $filters.Keys) {
        $ids = $filters[$channel] -split ',' | ForEach-Object { "EventID=$_" }
        $xpath = "*[System[($($ids -join ' or '))]]"

        try {
            $events = Get-WinEvent -LogName $channel -FilterXPath $xpath -MaxEvents 50 -ErrorAction Stop |
                Where-Object { $_.RecordId -gt $lastRecordId[$channel] } |
                Sort-Object RecordId
        } catch {
            $events = @()
        }

        foreach ($ev in $events) {
            $xml = [xml]$ev.ToXml()
            $data = @{}
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $data[$d.Name] = $d.'#text' }
            }

            # El Message completo puede pesar varios KB (toda la info de
            # sesión/proceso/red) -- suficientemente grande como para
            # que el paquete UDP se fragmente y algunos NAT/firewalls lo
            # descarten en silencio. Los campos estructurados importantes
            # ya se mandan aparte, no hace falta el texto completo.
            $shortMsg = $ev.Message
            if ($shortMsg -and $shortMsg.Length -gt 200) {
                $shortMsg = $shortMsg.Substring(0, 200)
            }

            $record = [ordered]@{
                EventID         = $ev.Id
                Channel         = $channel
                Hostname        = $hostname
                EventTime       = $ev.TimeCreated.ToString("o")
                Message         = $shortMsg
                TargetUserName  = $data["TargetUserName"]
                IpAddress       = $data["IpAddress"]
                LogonType       = $data["LogonType"]
                WorkstationName = $data["WorkstationName"]
                ServiceName     = $data["ServiceName"]
                ImagePath       = $data["ImagePath"]
                TaskName        = $data["TaskName"]
                SubjectUserName = $data["SubjectUserName"]
            }

            $json = $record | ConvertTo-Json -Compress
            # Formato fijo en inglés (InvariantCulture) a propósito --
            # en un Windows en español, Get-Date -Format "MMM" da "jul."
            # (con punto), lo que rompe el parseo del header de syslog
            # del lado de SENTINEL. Costó una sesión completa de debugging
            # encontrar este bug -- no quitar el InvariantCulture.
            $ts = (Get-Date).ToString("MMM dd HH:mm:ss", $invariant)
            $line = "<134>$ts $hostname sentinel_winlog: $json"
            $bytes = [System.Text.Encoding]::ASCII.GetBytes($line)

            try {
                $udpClient.Send($bytes, $bytes.Length, $SentinelHost, $SentinelPort) | Out-Null
            } catch {
                # Sin conectividad momentánea -- no se detiene el loop,
                # se reintenta en el próximo ciclo con el próximo evento.
            }

            $lastRecordId[$channel] = $ev.RecordId
        }
    }
    Start-Sleep -Seconds $PollSeconds
}
