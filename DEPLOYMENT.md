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

```bash
sudo apt install -y nginx
sudo cp deploy/nginx/sentinel.conf /etc/nginx/sites-available/sentinel
sudo ln -s /etc/nginx/sites-available/sentinel /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default
sudo nginx -t
sudo systemctl reload nginx
```

## 9. Abrir SENTINEL desde tu PC

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
