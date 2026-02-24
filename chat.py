import json
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import tkinter as tk
import base64
from datetime import datetime
from tkinter import filedialog, messagebox, scrolledtext
from urllib.parse import urlsplit

try:
    import socks
except ImportError:
    socks = None

try:
    from stem.control import Controller
except ImportError:
    Controller = None


class TorChatApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("OnionChatF3nix")
        self.root.attributes("-fullscreen", True)
        self.root.configure(bg="#e9eef6")

        self.sock = None
        self.server_sock = None
        self.running = False
        self.receiver_thread = None
        self.host_thread = None

        self.controller = None
        self.onion_service_id = None
        self.incoming = queue.Queue()

        self.local_port = tk.IntVar(value=5000)
        self.socks_host = tk.StringVar(value="127.0.0.1")
        self.socks_port = tk.IntVar(value=9050)
        self.control_port = tk.IntVar(value=9051)
        self.control_password = tk.StringVar(value="")
        self.onion_target = tk.StringVar()
        self.my_onion = tk.StringVar(value="-")
        self.my_name = tk.StringVar(value="Usuario")
        self.peer_name = tk.StringVar(value="Desconocido")
        self.tor_geo = tk.StringVar(value="Tor salida: --")
        self.conn_state_text = tk.StringVar(value="DESCONECTADO")
        self.theme_mode = tk.StringVar(value="dark")
        self.auto_reconnect = tk.BooleanVar(value=True)
        self.reconnect_delay_sec = tk.IntVar(value=5)
        self.ui_font = "Segoe UI" if sys.platform.startswith("win") else "DejaVu Sans"
        self.app_dir = os.path.dirname(os.path.abspath(__file__))
        self.main_script = os.path.join(self.app_dir, "main.py")
        self.conn_state_level = "down"
        self.connection_role = None
        self.manual_disconnect = True
        self.last_target_onion = ""
        self.reconnect_job = None
        self.themes = {
            "dark": {
                "root_bg": "#12161f",
                "panel_bg": "#1a2130",
                "header_bg": "#0f766e",
                "header_fg": "#f3fffc",
                "subtle_fg": "#9db0c8",
                "status_fg": "#c8ffe9",
                "geo_fg": "#ffe5a8",
                "input_bg": "#0f1726",
                "input_fg": "#e7eefc",
                "chat_bg": "#0b1220",
                "chat_fg": "#d7e2f7",
                "sys_fg": "#9fb0cc",
                "me_head_fg": "#8df4d6",
                "peer_head_fg": "#8cb7ff",
                "me_msg_bg": "#134e4a",
                "peer_msg_bg": "#283247",
                "btn_fg": "#f7fbff",
                "btn_detect_bg": "#7c6232",
                "btn_geo_bg": "#5f3f7f",
                "btn_host_bg": "#2f7f51",
                "btn_connect_bg": "#2c5f9e",
                "btn_disconnect_bg": "#9e4038",
                "btn_send_bg": "#0f766e",
                "btn_theme_bg": "#3b4a66",
                "entry_readonly_bg": "#25324a",
            },
            "light": {
                "root_bg": "#e9eef6",
                "panel_bg": "#e9eef6",
                "header_bg": "#0c8f7f",
                "header_fg": "#ffffff",
                "subtle_fg": "#23354f",
                "status_fg": "#d7fbe9",
                "geo_fg": "#fff5c2",
                "input_bg": "#ffffff",
                "input_fg": "#0f172a",
                "chat_bg": "#f8fafc",
                "chat_fg": "#111827",
                "sys_fg": "#6b7280",
                "me_head_fg": "#0f766e",
                "peer_head_fg": "#1e40af",
                "me_msg_bg": "#d1fae5",
                "peer_msg_bg": "#e5e7eb",
                "btn_fg": "#0f172a",
                "btn_detect_bg": "#fff3cd",
                "btn_geo_bg": "#f7e6ff",
                "btn_host_bg": "#c9f0d4",
                "btn_connect_bg": "#d4e7ff",
                "btn_disconnect_bg": "#ffd9cf",
                "btn_send_bg": "#0c8f7f",
                "btn_theme_bg": "#d6deeb",
                "entry_readonly_bg": "#edf2fa",
            },
        }

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(100, self.process_incoming)
        self.root.after(400, self.detect_tor)

    def _pip_hint(self, package: str) -> str:
        return f"{sys.executable} -m pip install {package}"

    def _build_ui(self):
        self.header = tk.Frame(self.root, padx=10, pady=8)
        self.header.pack(fill=tk.X)

        self.title_label = tk.Label(
            self.header,
            text="OnionChatF3nix",
            font=(self.ui_font, 14, "bold"),
        )
        self.title_label.pack(side=tk.LEFT)

        self.name_label = tk.Label(self.header, text="Tu nombre:")
        self.name_label.pack(side=tk.LEFT, padx=(24, 6))
        self.name_entry = tk.Entry(self.header, textvariable=self.my_name, width=18)
        self.name_entry.pack(side=tk.LEFT)
        self.btn_theme = tk.Button(self.header, text="Cambiar a Light", command=self.toggle_theme)
        self.btn_theme.pack(side=tk.LEFT, padx=(10, 0))
        self.btn_main = tk.Button(self.header, text="Ir a Toolkit", command=self.open_main_app)
        self.btn_main.pack(side=tk.LEFT, padx=(8, 0))
        self.btn_exit = tk.Button(self.header, text="Salir", command=self.on_close)
        self.btn_exit.pack(side=tk.LEFT, padx=(6, 0))

        self.right = tk.Frame(self.header)
        self.right.pack(side=tk.RIGHT)
        self.status_var = tk.StringVar(value="Listo. Tor debe estar activo en tu equipo.")
        self.geo_label = tk.Label(self.right, textvariable=self.tor_geo, font=(self.ui_font, 9))
        self.geo_label.pack(anchor="e")
        self.status_label = tk.Label(self.right, textvariable=self.status_var)
        self.status_label.pack(anchor="e")

        self.settings = tk.Frame(self.root, padx=10, pady=8)
        self.settings.pack(fill=tk.X)

        self.lbl_local_port = tk.Label(self.settings, text="Puerto local")
        self.lbl_local_port.grid(row=0, column=0, sticky="w")
        self.entry_local_port = tk.Entry(self.settings, textvariable=self.local_port, width=8)
        self.entry_local_port.grid(row=0, column=1, padx=4)

        self.lbl_socks_host = tk.Label(self.settings, text="SOCKS host")
        self.lbl_socks_host.grid(row=0, column=2, sticky="w", padx=(12, 0))
        self.entry_socks_host = tk.Entry(self.settings, textvariable=self.socks_host, width=12)
        self.entry_socks_host.grid(row=0, column=3, padx=4)

        self.lbl_socks_port = tk.Label(self.settings, text="Puerto SOCKS")
        self.lbl_socks_port.grid(row=0, column=4, sticky="w")
        self.entry_socks_port = tk.Entry(self.settings, textvariable=self.socks_port, width=8)
        self.entry_socks_port.grid(row=0, column=5, padx=4)

        self.lbl_control_port = tk.Label(self.settings, text="ControlPort")
        self.lbl_control_port.grid(row=0, column=6, sticky="w")
        self.entry_control_port = tk.Entry(self.settings, textvariable=self.control_port, width=8)
        self.entry_control_port.grid(row=0, column=7, padx=4)

        self.lbl_control_pass = tk.Label(self.settings, text="Control pass")
        self.lbl_control_pass.grid(row=0, column=8, sticky="w")
        self.entry_control_pass = tk.Entry(self.settings, textvariable=self.control_password, width=14, show="*")
        self.entry_control_pass.grid(row=0, column=9, padx=4)

        self.actions = tk.Frame(self.root, padx=10, pady=4)
        self.actions.pack(fill=tk.X)

        self.btn_detect_tor = tk.Button(self.actions, text="Detectar Tor", command=self.detect_tor)
        self.btn_detect_tor.pack(side=tk.LEFT, padx=2)
        self.btn_refresh_geo = tk.Button(self.actions, text="Actualizar salida Tor", command=self.refresh_tor_geo)
        self.btn_refresh_geo.pack(side=tk.LEFT, padx=4)
        self.btn_host = tk.Button(self.actions, text="Crear chat onion", command=self.start_host)
        self.btn_host.pack(side=tk.LEFT, padx=6)

        self.lbl_my_onion = tk.Label(self.actions, text="Tu onion:")
        self.lbl_my_onion.pack(side=tk.LEFT, padx=(14, 4))
        self.entry_my_onion = tk.Entry(self.actions, textvariable=self.my_onion, width=40, state="readonly")
        self.entry_my_onion.pack(side=tk.LEFT)
        self.btn_copy = tk.Button(self.actions, text="Copiar", command=self.copy_my_onion)
        self.btn_copy.pack(side=tk.LEFT, padx=4)

        self.connect = tk.Frame(self.root, padx=10, pady=4)
        self.connect.pack(fill=tk.X)

        self.lbl_connect_onion = tk.Label(self.connect, text="Conectar a onion:")
        self.lbl_connect_onion.pack(side=tk.LEFT)
        self.entry_onion_target = tk.Entry(self.connect, textvariable=self.onion_target, width=48)
        self.entry_onion_target.pack(side=tk.LEFT, padx=6)
        self.btn_connect = tk.Button(self.connect, text="Conectar", command=self.connect_to_onion)
        self.btn_connect.pack(side=tk.LEFT, padx=2)
        self.btn_disconnect = tk.Button(self.connect, text="Desconectar", command=self.disconnect)
        self.btn_disconnect.pack(side=tk.LEFT, padx=2)
        self.chk_auto_reconnect = tk.Checkbutton(
            self.connect,
            text="Auto-reconexion",
            variable=self.auto_reconnect,
            onvalue=True,
            offvalue=False,
        )
        self.chk_auto_reconnect.pack(side=tk.LEFT, padx=(10, 2))

        self.peerbar = tk.Frame(self.root, padx=10, pady=2)
        self.peerbar.pack(fill=tk.X)
        self.lbl_peer_title = tk.Label(self.peerbar, text="Conversando con:")
        self.lbl_peer_title.pack(side=tk.LEFT)
        self.lbl_peer_name = tk.Label(self.peerbar, textvariable=self.peer_name, font=(self.ui_font, 10, "bold"))
        self.lbl_peer_name.pack(side=tk.LEFT, padx=4)
        self.lbl_conn_title = tk.Label(self.peerbar, text="Estado:")
        self.lbl_conn_title.pack(side=tk.LEFT, padx=(18, 4))
        self.lbl_conn_dot = tk.Label(self.peerbar, text="●", font=(self.ui_font, 10, "bold"))
        self.lbl_conn_dot.pack(side=tk.LEFT)
        self.lbl_conn_value = tk.Label(self.peerbar, textvariable=self.conn_state_text, font=(self.ui_font, 10, "bold"))
        self.lbl_conn_value.pack(side=tk.LEFT, padx=(4, 0))

        self.chat = scrolledtext.ScrolledText(
            self.root,
            state=tk.DISABLED,
            wrap=tk.WORD,
            bg="#f8fafc",
            font=(self.ui_font, 10),
            padx=10,
            pady=8,
        )
        self.chat.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        self.chat.tag_configure("sys", foreground="#6b7280", justify="center", spacing1=8, spacing3=8)
        self.chat.tag_configure("me_head", foreground="#0f766e", justify="right", spacing1=6)
        self.chat.tag_configure("me_msg", background="#d1fae5", justify="right", lmargin1=140, lmargin2=140, rmargin=12, spacing3=8)
        self.chat.tag_configure("peer_head", foreground="#1e40af", justify="left", spacing1=6)
        self.chat.tag_configure("peer_msg", background="#e5e7eb", justify="left", lmargin1=12, lmargin2=12, rmargin=140, spacing3=8)

        self.bottom = tk.Frame(self.root, padx=10, pady=10)
        self.bottom.pack(fill=tk.X)

        self.msg_entry = tk.Entry(self.bottom, font=(self.ui_font, 11))
        self.msg_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.msg_entry.bind("<Return>", lambda _e: self.send_message())
        self.btn_send = tk.Button(self.bottom, text="Enviar", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=8)
        self.btn_send_file = tk.Button(self.bottom, text="Enviar archivo", command=self.send_file)
        self.btn_send_file.pack(side=tk.LEFT, padx=4)
        self.apply_theme()
        self._apply_conn_state_style()

    def toggle_theme(self):
        if self.theme_mode.get() == "dark":
            self.theme_mode.set("light")
        else:
            self.theme_mode.set("dark")
        self.apply_theme()

    def apply_theme(self):
        t = self.themes[self.theme_mode.get()]
        self.root.configure(bg=t["root_bg"])

        for frame in [self.header, self.right, self.settings, self.actions, self.connect, self.peerbar, self.bottom]:
            frame.configure(bg=t["panel_bg"])
        self.header.configure(bg=t["header_bg"])
        self.right.configure(bg=t["header_bg"])

        for label in [
            self.title_label,
            self.name_label,
            self.geo_label,
            self.status_label,
            self.lbl_local_port,
            self.lbl_socks_host,
            self.lbl_socks_port,
            self.lbl_control_port,
            self.lbl_control_pass,
            self.lbl_my_onion,
            self.lbl_connect_onion,
            self.lbl_peer_title,
            self.lbl_peer_name,
            self.lbl_conn_title,
        ]:
            label.configure(bg=t["panel_bg"], fg=t["subtle_fg"])

        self.title_label.configure(bg=t["header_bg"], fg=t["header_fg"])
        self.name_label.configure(bg=t["header_bg"], fg=t["header_fg"])
        self.geo_label.configure(bg=t["header_bg"], fg=t["geo_fg"])
        self.status_label.configure(bg=t["header_bg"], fg=t["status_fg"])
        self.lbl_peer_name.configure(fg=t["peer_head_fg"])

        for entry in [
            self.name_entry,
            self.entry_local_port,
            self.entry_socks_host,
            self.entry_socks_port,
            self.entry_control_port,
            self.entry_control_pass,
            self.entry_onion_target,
            self.msg_entry,
        ]:
            entry.configure(
                bg=t["input_bg"],
                fg=t["input_fg"],
                insertbackground=t["input_fg"],
                relief=tk.FLAT,
                highlightthickness=1,
                highlightbackground=t["panel_bg"],
                highlightcolor=t["header_bg"],
            )
        self.entry_my_onion.configure(
            readonlybackground=t["entry_readonly_bg"],
            fg=t["input_fg"],
            disabledforeground=t["input_fg"],
            relief=tk.FLAT,
        )

        self.btn_theme.configure(bg=t["btn_theme_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_main.configure(bg=t["btn_connect_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_exit.configure(bg=t["btn_disconnect_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_detect_tor.configure(bg=t["btn_detect_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_refresh_geo.configure(bg=t["btn_geo_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_host.configure(bg=t["btn_host_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_copy.configure(bg=t["btn_theme_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_connect.configure(bg=t["btn_connect_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_disconnect.configure(bg=t["btn_disconnect_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.btn_send.configure(bg=t["btn_send_bg"], fg="#ffffff", activebackground=t["panel_bg"], activeforeground="#ffffff")
        self.btn_send_file.configure(bg=t["btn_theme_bg"], fg=t["btn_fg"], activebackground=t["panel_bg"], activeforeground=t["btn_fg"])
        self.chk_auto_reconnect.configure(
            bg=t["panel_bg"],
            fg=t["subtle_fg"],
            activebackground=t["panel_bg"],
            activeforeground=t["subtle_fg"],
            selectcolor=t["panel_bg"],
        )

        if self.theme_mode.get() == "dark":
            self.btn_theme.configure(text="Cambiar a Light")
        else:
            self.btn_theme.configure(text="Cambiar a Dark")

        self.chat.configure(bg=t["chat_bg"], fg=t["chat_fg"], insertbackground=t["chat_fg"])
        self.chat.tag_configure("sys", foreground=t["sys_fg"], justify="center", spacing1=8, spacing3=8)
        self.chat.tag_configure("me_head", foreground=t["me_head_fg"], justify="right", spacing1=6)
        self.chat.tag_configure("me_msg", background=t["me_msg_bg"], foreground=t["chat_fg"], justify="right", lmargin1=140, lmargin2=140, rmargin=12, spacing3=8)
        self.chat.tag_configure("peer_head", foreground=t["peer_head_fg"], justify="left", spacing1=6)
        self.chat.tag_configure("peer_msg", background=t["peer_msg_bg"], foreground=t["chat_fg"], justify="left", lmargin1=12, lmargin2=12, rmargin=140, spacing3=8)
        self._apply_conn_state_style()

    def set_status(self, text: str):
        self.status_var.set(text)

    def _conn_colors(self):
        if self.theme_mode.get() == "dark":
            return {
                "connected": "#22c55e",
                "connecting": "#f59e0b",
                "retry": "#f59e0b",
                "down": "#ef4444",
            }
        return {
            "connected": "#15803d",
            "connecting": "#b45309",
            "retry": "#b45309",
            "down": "#b91c1c",
        }

    def _apply_conn_state_style(self):
        color = self._conn_colors().get(self.conn_state_level, self._conn_colors()["down"])
        panel_bg = self.themes[self.theme_mode.get()]["panel_bg"]
        self.lbl_conn_title.configure(bg=panel_bg, fg=self.themes[self.theme_mode.get()]["subtle_fg"])
        self.lbl_conn_dot.configure(bg=panel_bg, fg=color)
        self.lbl_conn_value.configure(bg=panel_bg, fg=color)

    def set_conn_state(self, level: str, text: str):
        self.conn_state_level = level
        self.conn_state_text.set(text)
        self._apply_conn_state_style()

    def _cancel_reconnect(self):
        if self.reconnect_job is not None:
            self.root.after_cancel(self.reconnect_job)
            self.reconnect_job = None

    def _schedule_reconnect(self):
        if self.reconnect_job is not None:
            return
        if self.connection_role != "client" or self.manual_disconnect:
            return
        if not self.auto_reconnect.get():
            return
        target = self.last_target_onion.strip()
        if not target.endswith(".onion"):
            return

        wait_sec = max(2, int(self.reconnect_delay_sec.get()))
        self.set_conn_state("retry", f"REINTENTO EN {wait_sec}S")
        self.append_system(f"Conexion perdida. Reintentando en {wait_sec} segundos...")
        self.reconnect_job = self.root.after(wait_sec * 1000, self._retry_connect)

    def _retry_connect(self):
        self.reconnect_job = None
        if self.running or self.manual_disconnect:
            return
        if self.connection_role != "client" or not self.auto_reconnect.get():
            return

        target = self.last_target_onion.strip()
        if not target.endswith(".onion"):
            return

        self.running = True
        self.set_status("Reintentando conexion por Tor...")
        self.set_conn_state("connecting", "RECONECTANDO")
        threading.Thread(target=self._connect_thread, args=(target,), daemon=True).start()

    def copy_my_onion(self):
        value = self.my_onion.get().strip()
        if value and value != "-":
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.append_system("Direccion onion copiada al portapapeles.")

    def append_system(self, text: str):
        self._append_line(text, "sys")

    def append_chat(self, sender: str, text: str, is_me: bool):
        now = datetime.now().strftime("%H:%M")
        head = f"{sender}  {now}"
        if is_me:
            self._append_line(head, "me_head")
            self._append_line(text, "me_msg")
        else:
            self._append_line(head, "peer_head")
            self._append_line(text, "peer_msg")

    def _append_line(self, text: str, tag: str):
        self.chat.configure(state=tk.NORMAL)
        self.chat.insert(tk.END, text + "\n", tag)
        self.chat.see(tk.END)
        self.chat.configure(state=tk.DISABLED)

    def _send_packet(self, data: dict):
        if not self.sock:
            return
        payload = json.dumps(data, ensure_ascii=False) + "\n"
        self.sock.sendall(payload.encode("utf-8"))

    def _flag_from_country_code(self, code: str) -> str:
        if not code or len(code) != 2:
            return "🏳"
        base = 127397
        return chr(base + ord(code[0].upper())) + chr(base + ord(code[1].upper()))

    def _http_get_over_tor(self, url: str, timeout: float = 20.0) -> str:
        if socks is None:
            raise RuntimeError("PySocks no instalado.")

        parsed = urlsplit(url)
        scheme = parsed.scheme or "https"
        host = parsed.hostname
        if not host:
            raise RuntimeError("URL invalida.")
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        port = parsed.port or (443 if scheme == "https" else 80)

        socks_port = self._resolve_socks_port()
        raw = socks.socksocket()
        raw.set_proxy(socks.SOCKS5, self.socks_host.get().strip() or "127.0.0.1", socks_port)
        raw.settimeout(timeout)
        raw.connect((host, port))

        conn = raw
        if scheme == "https":
            context = ssl.create_default_context()
            conn = context.wrap_socket(raw, server_hostname=host)

        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: OnionChat/1.0\r\n"
            "Connection: close\r\n\r\n"
        )
        conn.sendall(req.encode("ascii"))

        chunks = []
        while True:
            data = conn.recv(4096)
            if not data:
                break
            chunks.append(data)
        conn.close()

        response = b"".join(chunks)
        _, _, body = response.partition(b"\r\n\r\n")
        return body.decode("utf-8", errors="replace")

    def refresh_tor_geo(self):
        threading.Thread(target=self._refresh_tor_geo_thread, daemon=True).start()

    def _refresh_tor_geo_thread(self):
        try:
            tor_info_raw = self._http_get_over_tor("https://check.torproject.org/api/ip")
            tor_info = json.loads(tor_info_raw)
            if not tor_info.get("IsTor"):
                raise RuntimeError("La peticion no salio por Tor.")

            ip = tor_info.get("IP", "").strip()
            if not ip:
                raise RuntimeError("No se pudo obtener IP de salida.")

            geo_raw = self._http_get_over_tor(f"https://ipapi.co/{ip}/json/")
            geo = json.loads(geo_raw)

            country = geo.get("country_name") or "Desconocido"
            code = geo.get("country_code") or ""
            flag = self._flag_from_country_code(code)
            city = geo.get("city") or ""
            detail = f"{flag} {country}"
            if city:
                detail = f"{detail}, {city}"
            detail = f"{detail} ({ip})"

            self.incoming.put(("tor_geo", f"Tor salida: {detail}"))
            self.incoming.put(("system", f"Salida Tor detectada: {detail}"))
        except Exception as exc:
            self.incoming.put(("tor_geo", "Tor salida: no disponible"))
            self.incoming.put(("system", f"No se pudo consultar salida Tor: {exc}"))

    def _is_port_open(self, host: str, port: int, timeout: float = 1.2) -> bool:
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True
        except OSError:
            return False

    def detect_tor(self):
        host = self.socks_host.get().strip() or "127.0.0.1"

        socks_candidates = [9050, 9150]
        control_candidates = [9051, 9151]

        current_socks = int(self.socks_port.get())
        current_ctrl = int(self.control_port.get())

        socks_ports = [current_socks] + [p for p in socks_candidates if p != current_socks]
        control_ports = [current_ctrl] + [p for p in control_candidates if p != current_ctrl]

        found_socks = next((p for p in socks_ports if self._is_port_open(host, p)), None)
        found_ctrl = next((p for p in control_ports if self._is_port_open(host, p)), None)

        if found_socks:
            self.socks_port.set(found_socks)
        if found_ctrl:
            self.control_port.set(found_ctrl)

        if found_socks and found_ctrl:
            self.set_status(f"Tor detectado: SOCKS {found_socks}, Control {found_ctrl}")
            self.append_system(f"Tor detectado correctamente en {host}.")
            self.refresh_tor_geo()
        elif found_socks and not found_ctrl:
            self.set_status(f"SOCKS {found_socks} activo, falta ControlPort")
            self.append_system("Tor SOCKS detectado, pero ControlPort no responde. Para crear .onion habilita ControlPort 9051 o 9151.")
            self.refresh_tor_geo()
        else:
            self.set_status("Tor no detectado")
            self.append_system("No se detecto Tor en 9050/9150 ni ControlPort 9051/9151. Inicia Tor o Tor Browser.")

    def _connect_controller(self):
        host = self.socks_host.get().strip() or "127.0.0.1"
        preferred = int(self.control_port.get())
        candidates = [preferred, 9051, 9151]

        seen = set()
        last_error = None
        for port in candidates:
            if port in seen:
                continue
            seen.add(port)
            try:
                controller = Controller.from_port(address=host, port=port)
                password = self.control_password.get().strip()
                if password:
                    controller.authenticate(password=password)
                else:
                    controller.authenticate()

                if port != preferred:
                    self.incoming.put(("control_port", port))
                    self.incoming.put(("system", f"ControlPort detectado automaticamente en {port}."))
                return controller
            except Exception as exc:
                last_error = exc

        raise RuntimeError(
            "No se pudo conectar/autenticar con ControlPort. "
            "Asegura Tor activo y ControlPort habilitado (9051 o 9151)."
        ) from last_error

    def start_host(self):
        if Controller is None:
            messagebox.showerror("Falta dependencia", f"Instala stem:\n{self._pip_hint('stem')}")
            return
        if self.running:
            messagebox.showwarning("Sesion activa", "Ya tienes una conexion activa.")
            return

        self._cancel_reconnect()
        self.manual_disconnect = False
        self.connection_role = "host"
        self.last_target_onion = ""
        self.running = True
        self.set_status("Creando servicio onion...")
        self.set_conn_state("connecting", "ESPERANDO PEER")
        self.host_thread = threading.Thread(target=self._host_thread, daemon=True)
        self.host_thread.start()

    def _host_thread(self):
        try:
            local_port = int(self.local_port.get())

            self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_sock.bind(("127.0.0.1", local_port))
            self.server_sock.listen(1)
            self.server_sock.settimeout(1.0)

            self.controller = self._connect_controller()
            onion_service = self.controller.create_ephemeral_hidden_service({80: local_port}, await_publication=True)
            self.onion_service_id = onion_service.service_id
            onion = f"{onion_service.service_id}.onion"

            self.incoming.put(("onion", onion))
            self.incoming.put(("status", "Onion creado. Esperando conexion..."))
            self.incoming.put(("system", "Comparte tu direccion onion con la otra persona."))

            while self.running:
                try:
                    conn, _ = self.server_sock.accept()
                    self.sock = conn
                    self.incoming.put(("status", "Conexion establecida por Tor."))
                    self.incoming.put(("system", "La otra persona se conecto."))
                    self.incoming.put(("conn_state", ("connected", "CONECTADO")))
                    self._send_hello()
                    self._start_receiver(conn)
                    return
                except socket.timeout:
                    continue
        except Exception as exc:
            self.incoming.put(("status", "Error al crear host onion."))
            self.incoming.put(("system", f"Error host: {exc}"))
            self.incoming.put(("conn_state", ("down", "DESCONECTADO")))
            self.incoming.put(("system", "Tip: abre Tor Browser y pulsa 'Detectar Tor'. Si falla, revisa ControlPort y autenticacion."))
            self.running = False
            self._cleanup_host()

    def connect_to_onion(self):
        if socks is None:
            messagebox.showerror("Falta dependencia", f"Instala PySocks:\n{self._pip_hint('pysocks')}")
            return
        if self.running:
            messagebox.showwarning("Sesion activa", "Ya tienes una conexion activa.")
            return

        target = self._normalize_onion(self.onion_target.get().strip())
        if not target.endswith(".onion"):
            messagebox.showwarning("Onion invalido", "Debes ingresar una direccion .onion valida.")
            return

        self._cancel_reconnect()
        self.connection_role = "client"
        self.manual_disconnect = False
        self.last_target_onion = target
        self.running = True
        self.set_status("Conectando por Tor...")
        self.set_conn_state("connecting", "CONECTANDO")
        threading.Thread(target=self._connect_thread, args=(target,), daemon=True).start()

    def _resolve_socks_port(self) -> int:
        host = self.socks_host.get().strip() or "127.0.0.1"
        preferred = int(self.socks_port.get())
        candidates = [preferred, 9050, 9150]

        seen = set()
        for port in candidates:
            if port in seen:
                continue
            seen.add(port)
            if self._is_port_open(host, port):
                if port != preferred:
                    self.incoming.put(("socks_port", port))
                    self.incoming.put(("system", f"SOCKS detectado automaticamente en {port}."))
                return port

        raise RuntimeError("No hay SOCKS de Tor activo en 9050/9150. Inicia Tor o Tor Browser.")

    def _connect_thread(self, target: str):
        s = None
        try:
            socks_port = self._resolve_socks_port()
            s = socks.socksocket()
            s.set_proxy(socks.SOCKS5, self.socks_host.get().strip() or "127.0.0.1", socks_port)
            s.settimeout(30)
            s.connect((target, 80))
            self.sock = s

            self.incoming.put(("status", "Conectado por Tor."))
            self.incoming.put(("system", f"Conectado al chat onion: {target}"))
            self.incoming.put(("conn_state", ("connected", "CONECTADO")))
            self._send_hello()
            self._start_receiver(s)
        except Exception as exc:
            self.incoming.put(("status", "No se pudo conectar."))
            self.incoming.put(("system", f"Error conexion: {exc}"))
            self.incoming.put(("conn_state", ("down", "DESCONECTADO")))
            self.incoming.put(("schedule_reconnect", None))
            self.running = False
            if s:
                try:
                    s.close()
                except Exception:
                    pass

    def _normalize_onion(self, target: str) -> str:
        clean = target.replace("http://", "").replace("https://", "").strip().strip("/")
        if ":" in clean:
            clean = clean.split(":", 1)[0]
        return clean

    def _send_hello(self):
        try:
            self._send_packet({"type": "hello", "name": self.my_name.get().strip() or "Usuario"})
        except Exception:
            pass

    def _start_receiver(self, conn: socket.socket):
        self.receiver_thread = threading.Thread(target=self._recv_loop, args=(conn,), daemon=True)
        self.receiver_thread.start()

    def _recv_loop(self, conn: socket.socket):
        buffer = b""
        try:
            conn.settimeout(1.0)
            while self.running:
                try:
                    data = conn.recv(4096)
                    if not data:
                        self.incoming.put(("system", "La otra persona cerro la conexion."))
                        self.incoming.put(("status", "Desconectado."))
                        self.incoming.put(("conn_state", ("down", "DESCONECTADO")))
                        self.incoming.put(("schedule_reconnect", None))
                        self.running = False
                        break
                    buffer += data

                    while b"\n" in buffer:
                        raw, buffer = buffer.split(b"\n", 1)
                        if not raw.strip():
                            continue
                        self._handle_packet(raw)
                except socket.timeout:
                    continue
        except Exception as exc:
            if self.running:
                self.incoming.put(("system", f"Error de recepcion: {exc}"))
                self.incoming.put(("conn_state", ("down", "DESCONECTADO")))
                self.incoming.put(("schedule_reconnect", None))
        finally:
            try:
                conn.close()
            except Exception:
                pass
            self.running = False

    def _handle_packet(self, raw: bytes):
        try:
            packet = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError:
            text = raw.decode("utf-8", errors="replace")
            self.incoming.put(("message", {"sender": self.peer_name.get(), "text": text, "is_me": False}))
            return

        ptype = packet.get("type")
        if ptype == "hello":
            name = packet.get("name", "Desconocido").strip() or "Desconocido"
            self.incoming.put(("peer", name))
            self.incoming.put(("system", f"Ahora conversas con {name}."))
        elif ptype == "msg":
            text = str(packet.get("text", "")).strip()
            if text:
                self.incoming.put(("message", {"sender": self.peer_name.get(), "text": text, "is_me": False}))
        elif ptype == "file":
            name = str(packet.get("name", "")).strip()
            data = str(packet.get("data", ""))
            size = int(packet.get("size", 0))
            if name and data:
                self.incoming.put(("file", {"name": name, "data": data, "size": size}))

    def send_message(self):
        if not self.running or not self.sock:
            messagebox.showwarning("Sin conexion", "Primero debes conectar con otra persona.")
            return

        text = self.msg_entry.get().strip()
        if not text:
            return

        try:
            self._send_packet({"type": "msg", "text": text})
            my_sender = self.my_name.get().strip() or "Yo"
            self.append_chat(my_sender, text, is_me=True)
            self.msg_entry.delete(0, tk.END)
        except Exception as exc:
            self.append_system(f"Error al enviar: {exc}")
            self.disconnect(user_initiated=False)

    def send_file(self):
        if not self.running or not self.sock:
            messagebox.showwarning("Sin conexion", "Primero debes conectar con otra persona.")
            return

        path = filedialog.askopenfilename(title="Selecciona un archivo para enviar")
        if not path:
            return

        try:
            max_bytes = 8 * 1024 * 1024
            size = os.path.getsize(path)
            if size > max_bytes:
                messagebox.showwarning("Archivo grande", "El archivo supera 8 MB. Envia uno mas pequeno.")
                return

            with open(path, "rb") as f:
                encoded = base64.b64encode(f.read()).decode("ascii")

            filename = os.path.basename(path)
            self._send_packet({"type": "file", "name": filename, "size": size, "data": encoded})
            my_sender = self.my_name.get().strip() or "Yo"
            self.append_chat(my_sender, f"[Archivo enviado] {filename} ({size} bytes)", is_me=True)
        except Exception as exc:
            self.append_system(f"Error al enviar archivo: {exc}")
            self.disconnect(user_initiated=False)

    def _handle_incoming_file(self, payload: dict):
        name = payload.get("name", "archivo")
        encoded = payload.get("data", "")
        size = int(payload.get("size", 0))

        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception:
            self.append_system("No se pudo decodificar el archivo recibido.")
            return

        if size and len(data) != size:
            self.append_system("Archivo recibido con tamano inconsistente.")
            return

        suggested_path = os.path.join(os.path.expanduser("~"), "Downloads", name)
        save_path = filedialog.asksaveasfilename(
            title="Guardar archivo recibido",
            initialfile=name,
            initialdir=os.path.dirname(suggested_path),
        )
        if not save_path:
            self.append_system(f"Archivo recibido descartado: {name}")
            return

        try:
            with open(save_path, "wb") as f:
                f.write(data)
            sender = self.peer_name.get().strip() or "Peer"
            self.append_chat(sender, f"[Archivo recibido] {os.path.basename(save_path)} ({len(data)} bytes)", is_me=False)
        except Exception as exc:
            self.append_system(f"No se pudo guardar el archivo recibido: {exc}")

    def process_incoming(self):
        while True:
            try:
                kind, payload = self.incoming.get_nowait()
            except queue.Empty:
                break

            if kind == "status":
                self.set_status(payload)
            elif kind == "tor_geo":
                self.tor_geo.set(payload)
            elif kind == "system":
                self.append_system(payload)
            elif kind == "onion":
                self.my_onion.set(payload)
            elif kind == "peer":
                self.peer_name.set(payload)
            elif kind == "message":
                self.append_chat(payload["sender"], payload["text"], payload["is_me"])
            elif kind == "control_port":
                self.control_port.set(payload)
            elif kind == "socks_port":
                self.socks_port.set(payload)
            elif kind == "conn_state":
                self.set_conn_state(payload[0], payload[1])
            elif kind == "schedule_reconnect":
                self._schedule_reconnect()
            elif kind == "file":
                self._handle_incoming_file(payload)

        self.root.after(100, self.process_incoming)

    def _cleanup_host(self):
        if self.onion_service_id and self.controller:
            try:
                self.controller.remove_ephemeral_hidden_service(self.onion_service_id)
            except Exception:
                pass

        if self.controller:
            try:
                self.controller.close()
            except Exception:
                pass

        self.controller = None
        self.onion_service_id = None

    def disconnect(self, user_initiated: bool = True):
        self.manual_disconnect = user_initiated
        if user_initiated:
            self._cancel_reconnect()
        self.running = False

        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None

        self._cleanup_host()
        self.peer_name.set("Desconocido")
        if user_initiated:
            self.connection_role = None
        self.set_status("Desconectado.")
        self.set_conn_state("down", "DESCONECTADO")
        if user_initiated:
            self.append_system("Sesion cerrada.")
        else:
            self.append_system("Conexion cerrada.")

    def on_close(self):
        self.disconnect()
        self.root.destroy()

    def open_main_app(self):
        if not os.path.exists(self.main_script):
            messagebox.showerror("Archivo faltante", f"No se encontro: {self.main_script}")
            return
        self.disconnect()
        subprocess.Popen([sys.executable, self.main_script], cwd=self.app_dir)
        self.root.destroy()


def main():
    try:
        root = tk.Tk()
    except tk.TclError:
        print("No se pudo abrir la interfaz grafica. Verifica que tengas una sesion de escritorio activa.")
        return
    TorChatApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
