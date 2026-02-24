# F3NIX Toolkit + OnionChat
![WhatsApp Image 2026-02-24 at 14 51 06](https://github.com/user-attachments/assets/077605ea-8bd3-4ea3-a768-7d61cad286d6)
![WhatsApp Image 2026-02-24 at 14 51 06 (1)](https://github.com/user-attachments/assets/abf71280-1fbd-4a5b-8f86-6f1330b2910c)

Este proyecto incluye 2 aplicaciones de escritorio en Python (Tkinter):

- `main.py`: **F3NIX Toolkit** (archivos, red, metadatos y cifrado).
- `chat.py`: **OnionChatF3nix** (chat P2P sobre Tor con soporte de archivos).

## 1) F3NIX Toolkit (`main.py`)

### Funcionalidades principales

- Interfaz fullscreen con tema `dark/light`.
- Lista de archivos seleccionados:
  - agregar archivo,
  - abrir archivo seleccionado en el sistema (`xdg-open`/`open`/`os.startfile`),
  - eliminar archivo de la lista.
- Procesamiento de texto:
  - lee los `.txt` seleccionados,
  - extrae palabras unicas,
  - genera `resultado.txt` ordenado alfabeticamente.
- Escaneo de red local:
  - ejecuta `sudo arp-scan --localnet`,
  - pide contrasena sudo en la UI.
- Test de velocidad de internet:
  - descarga, subida, ping,
  - muestra detalles de servidor e ISP,
  - usa hilo + barra de progreso.
- IP publica y mapa:
  - consulta `https://ipinfo.io/json`,
  - muestra IP publica,
  - abre ubicacion aproximada en Google Maps.
- GPS en imagen EXIF:
  - abre imagen (`jpg/jpeg/png/tiff`),
  - extrae EXIF/GPS,
  - convierte DMS a decimal,
  - abre coordenadas en Google Maps si existen.
- Borrado de metadatos:
  - usa `exiftool -all= -overwrite_original`.
- Cifrado de carpetas:
  - comprime carpeta a ZIP temporal,
  - deriva clave con PBKDF2-HMAC-SHA256 (salt de 16 bytes, 100000 iteraciones),
  - cifra con Fernet,
  - guarda archivo `.f3nixcrypt` con formato `salt + datos_cifrados`.
- Descifrado de `.f3nixcrypt`:
  - lee salt y payload,
  - deriva clave con la contrasena,
  - descifra y extrae ZIP en carpeta destino.
- Integracion con chat:
  - boton para abrir `chat.py` desde `main.py`.

## 2) OnionChatF3nix (`chat.py`)

### Funcionalidades principales

- Interfaz fullscreen con tema `dark/light`.
- Nombre local editable y nombre del peer visible.
- Estados de conexion visibles:
  - `DESCONECTADO`,
  - `CONECTANDO`,
  - `CONECTADO`,
  - `REINTENTO EN Xs`.
- Deteccion automatica de Tor:
  - SOCKS en `9050/9150`,
  - ControlPort en `9051/9151`.
- Consulta de salida Tor:
  - valida salida por Tor con `check.torproject.org`,
  - consulta geolocalizacion de IP de salida (`ipapi.co`),
  - muestra pais, ciudad, IP y bandera.
- Modo host onion:
  - crea servicio onion efimero con `stem`,
  - publica tu `.onion`,
  - espera conexion entrante y arranca sesion.
- Modo cliente onion:
  - conecta por SOCKS5 (`PySocks`) a `.onion`,
  - normaliza input (quita `http/https`, puertos y `/`).
- Protocolo de mensajes por JSON sobre socket:
  - `hello`: intercambio de nombre,
  - `msg`: mensaje de chat,
  - `file`: transferencia de archivo en base64.
- Envio de archivos:
  - selector de archivo,
  - limite maximo de 8 MB por archivo.
- Recepcion de archivos:
  - valida base64 y tamano,
  - solicita ruta de guardado (`asksaveasfilename`).
- Reconexion automatica opcional (modo cliente) con delay configurable.
- Copiar direccion `.onion` al portapapeles.
- Boton para volver a `main.py`.

## Flujo de ejecucion

```bash
python3 main.py
# o
python3 chat.py
```

## Dependencias Python

- `speedtest-cli` (modulo `speedtest`)
- `requests`
- `Pillow`
- `cryptography`
- `PySocks` (modulo `socks`)
- `stem`

## Dependencias del sistema

- Entorno grafico activo (X11/Wayland/desktop session).
- `arp-scan` (para ARP scan en toolkit).
- `exiftool` (para borrar metadata).
- Tor activo localmente:
  - SOCKS en `9050` o `9150`,
  - ControlPort en `9051` o `9151` para crear host onion.

## Notas tecnicas

- Si no hay entorno grafico, ambas apps fallan con mensaje por consola.
- `resultado.txt` se genera en el directorio del proyecto.
- En cifrado/descifrado se usan archivos temporales y luego se eliminan.
  
- ## Aviso
Este proyecto es para fines educativos. No uses esta herramienta para actividades ilegales.
