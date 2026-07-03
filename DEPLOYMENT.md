# Desplegar SENTINEL en una VM propia (gratis)

Esta guía monta SENTINEL en una máquina virtual Ubuntu Server — cero costo,
sin depender de Streamlit Cloud. Los pasos de red/creación de la VM (1-5)
son específicos de dónde la hospedes; los de Docker/Nginx/hardening (6-10)
son iguales sin importar el proveedor.

**Dos rutas probadas:**
- **Hyper-V local** (pasos 1-5 tal como están abajo) — requiere permisos
  de administrador en Windows.
- **Oracle Cloud Free Tier** (la que terminamos usando) — no requiere
  admin local, corre en la nube con IP pública real. En vez de los pasos
  1-5, crea una instancia Compute con shape `VM.Standard.A1.Flex` (Ampere,
  Always Free hasta 4 OCPU/24GB), imagen Ubuntu 24.04, con tu llave SSH
  pública pegada al crearla. Si el toggle de IP pública sale bloqueado al
  crear la instancia (pasa en cuentas nuevas), créala sin IP, arráncala, y
  asígnasela después desde la VNIC adjunta. Luego abre el puerto 80 en la
  Security List de la VCN (Networking → Virtual Cloud Networks → tu VCN →
  Security Lists → Default Security List → Add Ingress Rules → 0.0.0.0/0,
  TCP, puerto 80).

---

## 1. Habilitar Hyper-V

Windows 11 Pro ya lo trae. Desde PowerShell **como administrador**:

```powershell
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V -All
```

Reinicia cuando lo pida.

## 2. Descargar Ubuntu Server

Descarga el ISO de **Ubuntu Server 24.04 LTS** desde
https://ubuntu.com/download/server (elige "Manual server installation").

## 3. Crear la VM

Abre **Hyper-V Manager** → Acción → Nueva → Máquina virtual:

- Nombre: `sentinel-vm`
- Generación: 2
- Memoria: 4096 MB (mínimo recomendado; 2048 MB si tu PC es limitada)
- Red: **Default Switch** (así la VM tiene internet vía NAT y es alcanzable desde tu PC)
- Disco duro: nuevo, 30 GB
- Instalación: "Instalar un sistema operativo desde un CD/DVD-ROM de arranque" → selecciona el ISO de Ubuntu

Antes de arrancar la VM, en su configuración desactiva **Secure Boot**
(Configuración → Seguridad) — Ubuntu instala pero a veces da problemas de
arranque con Secure Boot activado en Gen 2.

## 4. Instalar Ubuntu Server

Arranca la VM y sigue el instalador. Puntos importantes:

- Cuando pregunte por perfil de usuario, anota el username/password.
- En "SSH Setup" marca **Install OpenSSH server** (lo vas a necesitar para conectarte desde tu PC).
- El resto puedes dejarlo con los valores por defecto.

Al terminar, reinicia la VM.

## 5. Conectarte por SSH desde tu PC

Dentro de la VM, obtén su IP:
```bash
ip a
```
Busca la IP en la interfaz `eth0`/`enp0s...` (típicamente algo como `172.x.x.x` con Default Switch).

Desde PowerShell en tu PC:
```powershell
ssh tu_usuario@<ip-de-la-vm>
```

A partir de aquí, todos los comandos son **dentro de la VM** (por SSH).

## 6. Instalar Docker

```bash
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker $USER
```
Cierra la sesión SSH y vuelve a entrar para que el permiso de grupo `docker` tome efecto.

Verifica:
```bash
docker --version
docker compose version
```

## 7. Clonar el repo y levantar SENTINEL

```bash
sudo apt install -y git
git clone https://github.com/EmilianoMAl/siem-detection-system.git
cd siem-detection-system
cp .env.example .env
```

Edita `.env` y como mínimo genera un token para `SENTINEL_INGEST_TOKEN`
(lo vas a necesitar en el paso 11, pero no cuesta nada dejarlo listo ya):
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

```bash
docker compose up -d --build
```

Esto construye y levanta dos contenedores:
- `api` (FastAPI + motor de detección) en el puerto 8000
- `dashboard` (Streamlit) en el puerto 8501, que le habla a `api` por la red interna de Docker

Verifica que ambos estén corriendo:
```bash
docker compose ps
docker compose logs -f api        # Ctrl+C para salir
```

La primera vez que arranca, la API genera datos de demo para los 4 agentes
simulados — tarda unos segundos, lo verás en los logs.

## 8. Instalar y configurar Nginx

`deploy/nginx/sentinel.conf` protege todo el sitio con usuario/contraseña
(`auth_basic`) — hay que crear ese archivo de credenciales **antes** de
activar la configuración, si no Nginx no arranca:

```bash
sudo apt install -y nginx apache2-utils
sudo htpasswd -bc /etc/nginx/.htpasswd <tu-usuario> '<tu-contraseña>'
sudo chmod 640 /etc/nginx/.htpasswd
sudo chown root:www-data /etc/nginx/.htpasswd
```

Ahora sí, activa el sitio:

```bash
sudo cp deploy/nginx/sentinel.conf /etc/nginx/sites-available/sentinel
sudo ln -s /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

Para agregar o cambiar un usuario después (sin el `-c`, que borraría los
que ya había):
```bash
sudo htpasswd -b /etc/nginx/.htpasswd <usuario> '<contraseña-nueva>'
sudo systemctl reload nginx
```

> `/etc/nginx/.htpasswd` vive solo en la VM — nunca se commitea al repo.

## 9. Abrir SENTINEL desde tu PC

Te va a pedir usuario y contraseña (el `auth_basic` del paso anterior)
antes de mostrar cualquier página.

En el navegador de tu PC (el host, no la VM):
```
http://<ip-de-la-vm>/
```

Y la documentación interactiva de la API (Swagger):
```
http://<ip-de-la-vm>/api/docs
```

## 10. Hardening: doble capa de firewall

`docker-compose.yml` publica `api` y `dashboard` en `127.0.0.1:8000`/
`127.0.0.1:8501` (no en `0.0.0.0`) — solo Nginx, que corre en la misma
VM, puede llegar a ellos. Esto es necesario porque **Docker inserta sus
propias reglas de iptables para publicar puertos, y esas reglas pueden
saltarse el firewall del sistema operativo** — publicar en `0.0.0.0` deja
el puerto expuesto a internet sin importar qué diga `ufw`.

Con eso resuelto, activa `ufw` como segunda capa (la primera es la
Security List del proveedor cloud — en OCI, Networking → VCN → Security
Lists → agregar regla de ingreso para el puerto que necesites):

```bash
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
sudo ufw status verbose
```

Verifica desde tu PC que 8000/8501 ya no respondan directo (deben dar
timeout) y que el 80 siga funcionando normal.

**Gotcha real de ufw + Docker**: por default, `ufw` deniega la cadena
`FORWARD` (`DEFAULT_FORWARD_POLICY="DROP"` en `/etc/default/ufw`) — eso
bloquea las conexiones **salientes** de los contenedores hacia internet
(DNS resuelve bien, pero cualquier `urlopen`/`requests` desde dentro de
un contenedor se cuelga hasta hacer timeout). Si algo dentro de la API
necesita salir a internet (como el mapa geográfico, que consulta
ip-api.com), corrige esto:
```bash
sudo sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
sudo ufw reload
```
Esto no reabre nada de lo que ya cerraste — sigue siendo `ufw` el que
decide qué entra por `INPUT` (22/80/443 nada más); solo deja de bloquear
el tráfico que Docker reenvía hacia afuera.

## 11. Agente real: monitorear el tráfico genuino de esta VM

Hasta aquí SENTINEL solo corre datos simulados. Esta VM, al tener IP
pública, ya recibe tráfico real (bots escaneando el puerto 22, tráfico
oportunista al puerto 80) — `agent/ship_logs.py` manda ese tráfico real
a la API, sin dependencias externas (solo la librería estándar de Python).

**11.1 — Completa el `.env`** con el hostname/IP real de la VM y el mismo
token que generaste en el paso 7:
```bash
# En .env:
SENTINEL_REAL_AGENT_HOSTNAME=sentinel-vm
SENTINEL_REAL_AGENT_IP=<tu-ip-publica>
SENTINEL_INGEST_TOKEN=<el-token-que-generaste>
```
Aplica el cambio: `docker compose up -d` (recrea el contenedor `api` con
las nuevas variables — vas a ver en sus logs "Agente real registrado").

**11.2 — Dale permiso al usuario que corre el agente para leer los logs
del sistema** (auth.log solo lo puede leer root o el grupo `adm`):
```bash
sudo usermod -aG adm ubuntu
```

**11.3 — Crea el archivo de entorno para el servicio**:
```bash
sudo mkdir -p /etc/sentinel-agent
sudo tee /etc/sentinel-agent/env > /dev/null <<'EOF'
SENTINEL_API_URL=http://127.0.0.1:8000
SENTINEL_INGEST_TOKEN=<el-mismo-token-del-.env>
SENTINEL_AGENT_STATE=/var/lib/sentinel-agent/offsets.json
EOF
sudo chmod 600 /etc/sentinel-agent/env
```

**11.4 — Crea el servicio y el timer de systemd** (corre el script cada 30s):
```bash
sudo tee /etc/systemd/system/sentinel-agent.service > /dev/null <<EOF
[Unit]
Description=SENTINEL — envía logs reales de esta VM a la API

[Service]
Type=oneshot
EnvironmentFile=/etc/sentinel-agent/env
ExecStart=/usr/bin/python3 $HOME/siem-detection-system/agent/ship_logs.py
EOF

sudo tee /etc/systemd/system/sentinel-agent.timer > /dev/null <<'EOF'
[Unit]
Description=Corre sentinel-agent.service cada 30 segundos

[Timer]
OnBootSec=30
OnUnitActiveSec=30

[Install]
WantedBy=timers.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-agent.timer
```

**11.5 — Verifica que esté corriendo**:
```bash
sudo systemctl status sentinel-agent.timer
sudo journalctl -u sentinel-agent.service -f    # Ctrl+C para salir
```

Deberías ver líneas tipo `[ssh] N líneas enviadas -> {...}` cada 30
segundos. En el dashboard, el agente `agent-real-vm` va a pasar de
"NEVER_CONNECTED" a "ACTIVE" en cuanto llegue el primer envío.

> Nota de seguridad: el servicio corre como root porque `/var/log/auth.log`
> solo lo lee root o el grupo `adm` — para una VM personal de demo es un
> trade-off razonable, pero en un entorno más sensible conviene un usuario
> dedicado con permisos mínimos.

## 12. Syslog real: recibir logs de otra computadora (ej. un firewall SonicWall)

A diferencia del agente real (sección 11, que manda logs de esta misma
VM), esto es para recibir logs de **otro equipo** — típicamente un
firewall en tu trabajo, configurado para mandar syslog a esta VM. La
API ya trae un receptor de syslog (UDP 514) corriendo como tarea de
fondo (`engine/syslog_listener.py`) — no hace falta instalar nada
adicional en la VM, solo abrir el puerto con cuidado.

**⚠️ Este puerto NO pasa por Nginx ni por su contraseña** — syslog no
es HTTP, así que el Basic Auth del resto del sitio no aplica aquí. La
única protección real es el firewall, restringido a la IP/rango desde
donde de verdad vas a mandar tráfico.

**12.1 — Abre el puerto 514/UDP, restringido a tu origen conocido.**
Primero en la **OCI Security List** (Networking → VCN → Security Lists
→ Add Ingress Rule): protocolo UDP, puerto 514, "Source" = el CIDR de
tu red de trabajo (no `0.0.0.0/0`). Luego en `ufw`:
```bash
sudo ufw allow from <CIDR_RED_TRABAJO> to any port 514 proto udp
sudo ufw status verbose   # confirma que 514/udp NO quedó abierto a "Anywhere"
```
Si todavía no sabes el CIDR exacto, puedes abrirlo temporalmente a
cualquier origen (`sudo ufw allow 514/udp`) y restringirlo en cuanto lo
tengas — pero ten en cuenta que mientras tanto cualquiera en internet
podría mandarte syslog falso (se descarta solo si no matchea el
formato de SonicWall, no hay autenticación posible en el protocolo).

**12.2 — Identifica a cada cliente por su IP** en `.env`, con
`SENTINEL_SYSLOG_CLIENTS` (JSON: IP de origen → identidad del agente).
Cada dispositivo que mande syslog a este puerto (una VM Linux, una VM
de Windows, un firewall real, etc.) queda como su propio agente
separado en vez de mezclarse todos bajo uno solo:
```bash
# En .env (una sola línea, sin espacios extra):
SENTINEL_SYSLOG_CLIENTS={"200.66.80.91":{"agent_id":"agent-linux-wazuh","hostname":"wazuh-srv-Virtual-Machine","os":"Ubuntu Linux"},"<IP_WINDOWS>":{"agent_id":"agent-windows-01","hostname":"WIN-DESKTOP","os":"Windows"}}
```
Aplica con `docker compose up -d` (recrea `api` con las nuevas
variables y publica el puerto 514/udp definido en `docker-compose.yml`).
Si una IP manda tráfico sin estar en esta lista, igual se guarda —
SENTINEL le autogenera un agente (`agent-syslog-<ip-con-guiones>`, sin
nombre amigable) para no perder el dato — solo agrégala aquí cuando
tengas la IP real para que se vea con un nombre legible.

> Nota: las variables `SENTINEL_SYSLOG_AGENT_ID`/`SENTINEL_SYSLOG_HOSTNAME`/
> `SENTINEL_SYSLOG_IP` (de una versión anterior de esta guía) ya no las usa
> el receptor de syslog — la identificación ahora es por IP real de
> quien manda el paquete, no un agente fijo para todo. Se dejan sin
> quitar solo por compatibilidad con datos ya guardados bajo
> `agent-syslog-fw`.

**12.3 — Configura el SonicWall (o lo que mande los logs)** para
enviar syslog a `<ip-publica-de-esta-VM>:514` sobre UDP — esto se hace
del lado del firewall/dispositivo, no en esta VM. Para una VM Linux con
`rsyslog`, en esa otra VM:
```bash
sudo tee /etc/rsyslog.d/60-sentinel.conf > /dev/null <<EOF
*.* @<ip-publica-de-esta-VM>:514
EOF
sudo systemctl restart rsyslog
```
(el `@` simple es UDP; `*.*` manda todo lo que ese sistema logea —
se puede acotar a `auth,authpriv.*` para solo intentos de login).

**12.4 — Verifica que esté llegando**:
```bash
docker compose logs -f api | grep -i syslog
```
Las líneas se agrupan y procesan cada 15 segundos (igual que el agente
real agrupa por lotes) — en el dashboard, cambia el selector "Workspace"
a "VM real" y usa el selector "Agente" para ver los datos de cada
cliente por separado. La página "Events" muestra el detalle completo
de cada evento (no solo los que dispararon una alerta).

---

## Troubleshooting

**No carga nada / connection refused**
Revisa que Nginx esté activo (`sudo systemctl status nginx`) y que los
contenedores estén `Up` (`docker compose ps`).

**El dashboard carga pero se queda pegado / no actualiza**
Nginx necesita los headers de `Upgrade`/`Connection` para el websocket de
Streamlit — están en `deploy/nginx/sentinel.conf`; confirma que `nginx -t`
no marcó errores al copiar el archivo.

**`docker: permission denied`**
Te faltó cerrar sesión y volver a entrar por SSH después del
`usermod -aG docker`.

**La IP de la VM cambió**
Con Default Switch, Hyper-V asigna IP por DHCP y puede cambiar entre
reinicios. Corre `ip a` de nuevo en la VM, o configura una IP estática
en `/etc/netplan/*.yaml` si quieres que sea fija.

---

## Más adelante: exponerlo a internet real

Esta guía deja SENTINEL accesible solo dentro de tu red local (tu PC hacia
la VM). Si algún día quieres que otra persona lo vea desde fuera de tu casa
sin pagar por un VPS, las opciones son:
- **Cloudflare Tunnel** (gratis): expone la VM a internet sin abrir puertos
  en tu router.
- **Port forwarding en tu router** hacia la IP de la VM (menos seguro, no
  recomendado sin TLS).
- Migrar el mismo `docker-compose.yml` a un VPS real (Oracle Cloud Free
  Tier, DigitalOcean, etc.) cuando decidas pagar/usar una capa gratuita con
  IP pública — los pasos de Docker/Nginx de esta guía son los mismos.
