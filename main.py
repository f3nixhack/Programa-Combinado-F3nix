#F3NIX
import subprocess
import speedtest
import requests
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from PIL import Image, ImageTk
from PIL.ExifTags import TAGS, GPSTAGS
import webbrowser
import threading
import os
import shutil
import base64
import tempfile
import sys
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- UI Configuration (tema con switch claro/oscuro) ---
THEMES = {
    "dark": {
        "BG_COLOR": "#0A1116",
        "PANEL_COLOR": "#111B22",
        "PANEL_ALT_COLOR": "#142430",
        "FG_COLOR": "#EAF6FF",
        "MUTED_TEXT": "#AFC0CC",
        "ACCENT_COLOR": "#3DD6C6",
        "BUTTON_COLOR": "#1C2B36",
        "BUTTON_HOVER_COLOR": "#243947",
        "BUTTON_ACTIVE_COLOR": "#2B4A5B",
        "BUTTON_BORDER": "#2E4755",
        "BUTTON_ALERT_COLOR": "#5C1F2A",
        "BUTTON_ALERT_ACTIVE": "#7A2A37",
        "BUTTON_BORDER_ALERT": "#8A3544",
        "LISTBOX_BG": "#0F1A22",
        "LISTBOX_SELECT_FG": "#0A1116",
        "TEXT_BG": "#0E1A22",
        "TEXT_FG": "#D9F0FF",
        "PROGRESS_TROUGH": "#13222C",
    },
    "light": {
        "BG_COLOR": "#ECF3F8",
        "PANEL_COLOR": "#FFFFFF",
        "PANEL_ALT_COLOR": "#F7FBFF",
        "FG_COLOR": "#10202D",
        "MUTED_TEXT": "#4C6374",
        "ACCENT_COLOR": "#1CA39A",
        "BUTTON_COLOR": "#DCE9F3",
        "BUTTON_HOVER_COLOR": "#CBDCE9",
        "BUTTON_ACTIVE_COLOR": "#B9CFDF",
        "BUTTON_BORDER": "#9DB4C6",
        "BUTTON_ALERT_COLOR": "#E8C8CC",
        "BUTTON_ALERT_ACTIVE": "#DDAAB1",
        "BUTTON_BORDER_ALERT": "#C88D95",
        "LISTBOX_BG": "#F2F8FD",
        "LISTBOX_SELECT_FG": "#0A1116",
        "TEXT_BG": "#F6FBFF",
        "TEXT_FG": "#10202D",
        "PROGRESS_TROUGH": "#D7E6F2",
    },
}

CURRENT_THEME = "dark"

BG_COLOR = THEMES[CURRENT_THEME]["BG_COLOR"]
PANEL_COLOR = THEMES[CURRENT_THEME]["PANEL_COLOR"]
PANEL_ALT_COLOR = THEMES[CURRENT_THEME]["PANEL_ALT_COLOR"]
FG_COLOR = THEMES[CURRENT_THEME]["FG_COLOR"]
MUTED_TEXT = THEMES[CURRENT_THEME]["MUTED_TEXT"]
ACCENT_COLOR = THEMES[CURRENT_THEME]["ACCENT_COLOR"]
BUTTON_COLOR = THEMES[CURRENT_THEME]["BUTTON_COLOR"]
BUTTON_HOVER_COLOR = THEMES[CURRENT_THEME]["BUTTON_HOVER_COLOR"]
BUTTON_ACTIVE_COLOR = THEMES[CURRENT_THEME]["BUTTON_ACTIVE_COLOR"]
BUTTON_BORDER = THEMES[CURRENT_THEME]["BUTTON_BORDER"]
BUTTON_ALERT_COLOR = THEMES[CURRENT_THEME]["BUTTON_ALERT_COLOR"]
BUTTON_ALERT_ACTIVE = THEMES[CURRENT_THEME]["BUTTON_ALERT_ACTIVE"]
BUTTON_BORDER_ALERT = THEMES[CURRENT_THEME]["BUTTON_BORDER_ALERT"]
FONT_FAMILY = "Segoe UI" if sys.platform.startswith("win") else "DejaVu Sans"
FONT_SIZE_NORMAL = 10
FONT_SIZE_LARGE = 13

# --- Core Functions ---

# Variable global para el widget de texto de resultados
resultado_text = None
themed_buttons = []
APP_DIR = os.path.dirname(os.path.abspath(__file__))
CHAT_SCRIPT = os.path.join(APP_DIR, "chat.py")


def set_theme_values(theme_name):
    global CURRENT_THEME
    global BG_COLOR, PANEL_COLOR, PANEL_ALT_COLOR, FG_COLOR, MUTED_TEXT, ACCENT_COLOR
    global BUTTON_COLOR, BUTTON_HOVER_COLOR, BUTTON_ACTIVE_COLOR, BUTTON_BORDER
    global BUTTON_ALERT_COLOR, BUTTON_ALERT_ACTIVE, BUTTON_BORDER_ALERT

    CURRENT_THEME = theme_name
    theme = THEMES[theme_name]
    BG_COLOR = theme["BG_COLOR"]
    PANEL_COLOR = theme["PANEL_COLOR"]
    PANEL_ALT_COLOR = theme["PANEL_ALT_COLOR"]
    FG_COLOR = theme["FG_COLOR"]
    MUTED_TEXT = theme["MUTED_TEXT"]
    ACCENT_COLOR = theme["ACCENT_COLOR"]
    BUTTON_COLOR = theme["BUTTON_COLOR"]
    BUTTON_HOVER_COLOR = theme["BUTTON_HOVER_COLOR"]
    BUTTON_ACTIVE_COLOR = theme["BUTTON_ACTIVE_COLOR"]
    BUTTON_BORDER = theme["BUTTON_BORDER"]
    BUTTON_ALERT_COLOR = theme["BUTTON_ALERT_COLOR"]
    BUTTON_ALERT_ACTIVE = theme["BUTTON_ALERT_ACTIVE"]
    BUTTON_BORDER_ALERT = theme["BUTTON_BORDER_ALERT"]

def procesar_archivo(archivo):
    palabras = set()
    try:
        with open(archivo, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                palabras.update(line.split())
    except Exception as e:
        messagebox.showerror("Error de Archivo", f"No se pudo leer el archivo {archivo}:\n{e}")
    return palabras


def escribir_resultado(texto):
    """Escribir en el área de resultados desplazable."""
    global resultado_text
    if resultado_text is not None:
        try:
            resultado_text.config(state='normal')
            resultado_text.delete('1.0', tk.END)
            resultado_text.insert(tk.END, texto)
            resultado_text.config(state='disabled')
        except Exception:
            pass


def agregar_archivo():
    archivo = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt"), ("Imágenes", "*.jpg *.jpeg *.png *.tiff"), ("Todos", "*")])
    if archivo:
        archivos_seleccionados.append(archivo)
        update_selected_files_label()

def generar_resultado():
    if not archivos_seleccionados:
        messagebox.showwarning("Sin Archivos", "Por favor, agregue al menos un archivo de texto.")
        return

    palabras_unicas = set()
    for archivo in archivos_seleccionados:
        palabras_unicas.update(procesar_archivo(archivo))

    resultado_path = 'resultado.txt'
    try:
        with open(resultado_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(sorted(list(palabras_unicas))))
        escribir_resultado(f'Se han guardado {len(palabras_unicas)} palabras únicas en {resultado_path}')
    except Exception as e:
        messagebox.showerror("Error al Guardar", f"No se pudo guardar el archivo de resultado:\n{e}")

def escanear_arp():
    contrasena = contrasena_entry.get()
    if not contrasena:
        messagebox.showwarning("Contraseña Requerida", "Por favor, ingrese la contraseña de sudo.")
        return
    try:
        comando = 'sudo -S arp-scan --localnet'
        proceso = subprocess.Popen(comando.split(), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        resultado_arp, error = proceso.communicate(input=f'{contrasena}\n')
        if proceso.returncode == 0:
            escribir_resultado(f'Resultado de ARP Scan:\n{resultado_arp}')
        else:
            messagebox.showerror("Error de ARP Scan", f"Error al ejecutar arp-scan: {error}")
    except FileNotFoundError:
        messagebox.showerror("Comando no Encontrado", "El comando 'arp-scan' no se encontró. ¿Está instalado?")
    except Exception as e:
        messagebox.showerror("Error Inesperado", f"Ocurrió un error: {e}")

def medir_velocidad():
    
    def medir_velocidad_thread():
        try:
            st = speedtest.Speedtest()
            st.get_best_server()
            st.download()
            st.upload()
            results_dict = st.results.dict()

            descarga = results_dict['download'] / 1_000_000
            subida = results_dict['upload'] / 1_000_000
            ping = results_dict['ping']
            server_name = results_dict['server']['name']
            server_country = results_dict['server']['country']
            sponsor = results_dict['server']['sponsor']
            client_ip = results_dict['client']['ip']
            isp = results_dict['client']['isp']
            
            result_string = (
                f"Resultados del Test de Velocidad:\n\n"
                f"Descarga: {descarga:.2f} Mbps\n"
                f"Subida: {subida:.2f} Mbps\n"
                f"Ping: {ping:.2f} ms\n\n"
                f"--- Detalles del Servidor ---\n"
                f"Servidor: {server_name}, {server_country}\n"
                f"Patrocinador: {sponsor}\n\n"
                f"--- Detalles del Cliente ---\n"
                f"IP: {client_ip}\n"
                f"ISP: {isp}"
            )
            
            def update_ui():
                escribir_resultado(result_string)
                progress_bar.stop()
                progress_bar.pack_forget()

            ventana.after(0, update_ui)

        except Exception as e:
            def update_ui_error():
                messagebox.showerror("Error de Speedtest", f"No se pudo medir la velocidad: {e}")
                progress_bar.stop()
                progress_bar.pack_forget()
            
            ventana.after(0, update_ui_error)

    escribir_resultado("Midiendo velocidad de Internet... Por favor, espere.")
    progress_bar.pack(fill="x", pady=5, expand=True)
    progress_bar.start()
    ventana.update_idletasks()
    
    thread = threading.Thread(target=medir_velocidad_thread)
    thread.start()


def obtener_ip_y_abrir_mapa():
    try:
        escribir_resultado("Obteniendo información de IP...")
        ventana.update_idletasks()
        response = requests.get('https://ipinfo.io/json')
        response.raise_for_status()
        ip_info = response.json()
        ip = ip_info.get('ip', 'No disponible')
        loc = ip_info.get('loc', '')
        escribir_resultado(f'Tu IP pública es: {ip}')
        if loc:
            lat, lon = loc.split(',')
            maps_url = f'https://www.google.com/maps/place/{lat},{lon}'
            webbrowser.open(maps_url)
    except requests.RequestException as e:
        messagebox.showerror("Error de Red", f"No se pudo obtener la información de IP: {e}")

def elegir_y_borrar_metadatos():
    archivo = filedialog.askopenfilename(title="Seleccione un archivo para borrar sus metadatos")
    if not archivo:
        return
    try:
        # Usamos exiftool para borrar todos los metadatos
        comando = ["exiftool", "-all=", "-overwrite_original", archivo]
        resultado = subprocess.run(comando, check=True, capture_output=True, text=True)
        messagebox.showinfo("Éxito", f"Metadatos borrados exitosamente de:\n{archivo}")
    except FileNotFoundError:
        messagebox.showerror("ExifTool no Encontrado", "ExifTool no está instalado. Por favor, instálelo para usar esta función.")
    except subprocess.CalledProcessError as e:
        messagebox.showerror("Error de ExifTool", f"ExifTool falló con el siguiente error:\n{e.stderr}")
    except Exception as e:
        messagebox.showerror("Error Inesperado", f"Ocurrió un error: {e}")

def _derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_folder():
    folder_path = filedialog.askdirectory(title="Seleccione la carpeta para cifrar")
    if not folder_path:
        return

    password = simpledialog.askstring("Contraseña", "Ingrese la contraseña para el cifrado:", show='*')
    if not password:
        messagebox.showwarning("Cancelado", "Operación de cifrado cancelada.")
        return

    output_file = filedialog.asksaveasfilename(title="Guardar archivo cifrado como...",defaultextension=".f3nixcrypt", filetypes=[("F3nix Encrypted File", "*.f3nixcrypt")])
    if not output_file:
        return

    temp_archive = None
    temp_dir = None
    try:
        # 1. Comprimir la carpeta
        escribir_resultado(f"Comprimiendo {os.path.basename(folder_path)}...")
        ventana.update_idletasks()
        temp_dir = tempfile.mkdtemp(prefix="f3nix_encrypt_")
        archive_base = os.path.join(temp_dir, "archive")
        temp_archive = shutil.make_archive(archive_base, 'zip', folder_path)

        # 2. Derivar clave y cifrar
        escribir_resultado("Cifrando archivo...")
        ventana.update_idletasks()
        
        salt = os.urandom(16)
        key = _derive_key(password.encode(), salt)
        f = Fernet(key)

        with open(temp_archive, "rb") as file:
            file_data = file.read()
        
        encrypted_data = f.encrypt(file_data)

        # 3. Guardar archivo cifrado (salt + data)
        with open(output_file, "wb") as file:
            file.write(salt)
            file.write(encrypted_data)

        messagebox.showinfo("Éxito", f"Carpeta cifrada exitosamente en:\n{output_file}")

    except Exception as e:
        messagebox.showerror("Error de Cifrado", f"Ocurrió un error durante el cifrado: {e}")
    finally:
        # 4. Limpiar archivo temporal
        if temp_archive and os.path.exists(temp_archive):
            os.remove(temp_archive)
        if temp_dir and os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        escribir_resultado("Operación finalizada.")


def decrypt_folder():
    file_path = filedialog.askopenfilename(title="Seleccione el archivo .f3nixcrypt para descifrar", filetypes=[("F3nix Encrypted File", "*.f3nixcrypt")])
    if not file_path:
        return

    password = simpledialog.askstring("Contraseña", "Ingrese la contraseña para el descifrado:", show='*')
    if not password:
        messagebox.showwarning("Cancelado", "Operación de descifrado cancelada.")
        return
        
    output_dir = filedialog.askdirectory(title="Seleccione la carpeta de destino para extraer")
    if not output_dir:
        return

    temp_archive = None
    temp_dir = None
    try:
        # 1. Leer salt y datos cifrados
        escribir_resultado("Descifrando archivo...")
        ventana.update_idletasks()
        with open(file_path, "rb") as file:
            salt = file.read(16)
            encrypted_data = file.read()

        # 2. Derivar clave y descifrar
        key = _derive_key(password.encode(), salt)
        f = Fernet(key)
        
        try:
            decrypted_data = f.decrypt(encrypted_data)
        except InvalidToken:
            messagebox.showerror("Error de Descifrado", "Contraseña incorrecta o archivo corrupto.")
            return

        # 3. Guardar y extraer el archivo descomprimido
        escribir_resultado("Extrayendo archivos...")
        ventana.update_idletasks()
        temp_dir = tempfile.mkdtemp(prefix="f3nix_decrypt_")
        temp_archive = os.path.join(temp_dir, "archive_decrypted.zip")
        with open(temp_archive, "wb") as file:
            file.write(decrypted_data)
            
        shutil.unpack_archive(temp_archive, output_dir)

        messagebox.showinfo("Éxito", f"Archivo descifrado y extraído en:\n{output_dir}")

    except Exception as e:
        messagebox.showerror("Error de Descifrado", f"Ocurrió un error durante el descifrado: {e}")
    finally:
        # 4. Limpiar archivo temporal
        if temp_archive and os.path.exists(temp_archive):
            os.remove(temp_archive)
        if temp_dir and os.path.isdir(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)
        escribir_resultado("Operación finalizada.")


def get_exif_data(image):
    exif_data = {}
    info = image._getexif()
    if info:
        for tag, value in info.items():
            decoded = TAGS.get(tag, tag)
            if decoded == "GPSInfo":
                gps_data = {}
                for t in value:
                    sub_decoded = GPSTAGS.get(t, t)
                    gps_data[sub_decoded] = value[t]
                exif_data[decoded] = gps_data
            else:
                exif_data[decoded] = value
    return exif_data

def get_decimal_from_dms(dms, ref):
    degrees, minutes, seconds = dms
    decimal = float(degrees) + float(minutes) / 60 + float(seconds) / 3600
    if ref in ['S', 'W']:
        decimal = -decimal
    return decimal

def get_coordinates(exif_data):
    if 'GPSInfo' in exif_data:
        gps_info = exif_data['GPSInfo']
        lat_dms = gps_info.get('GPSLatitude')
        lon_dms = gps_info.get('GPSLongitude')
        lat_ref = gps_info.get('GPSLatitudeRef')
        lon_ref = gps_info.get('GPSLongitudeRef')

        if lat_dms and lon_dms and lat_ref and lon_ref:
            lat = get_decimal_from_dms(lat_dms, lat_ref)
            lon = get_decimal_from_dms(lon_dms, lon_ref)
            return lat, lon
    return None, None

def buscar_archivo_y_abrir_mapa():
    archivo = filedialog.askopenfilename(title="Seleccione un archivo de imagen", filetypes=[("Imágenes", "*.jpg *.jpeg *.png *.tiff")])
    if not archivo:
        return
    try:
        image = Image.open(archivo)
        exif_data = get_exif_data(image)
        lat, lon = get_coordinates(exif_data)
        if lat is not None and lon is not None:
            maps_url = f"https://www.google.com/maps/place/{lat},{lon}"
            webbrowser.open(maps_url)
        else:
            messagebox.showinfo("Sin GPS", "No se encontró información de GPS en esta imagen.")
        
        # Agregar la imagen a la lista de la izquierda para poder abrirla después
        if archivo not in archivos_seleccionados:
            archivos_seleccionados.append(archivo)
            update_selected_files_label()
            escribir_resultado(f"Imagen agregada a la lista: {os.path.basename(archivo)}")
    except Exception as e:
        messagebox.showerror("Error de Imagen", f"No se pudo procesar el archivo: {e}")

# --- UI Setup ---

def update_selected_files_label():
    # Actualiza el Listbox con los archivos seleccionados (más legible)
    listbox_selected.delete(0, tk.END)
    if archivos_seleccionados:
        for f in archivos_seleccionados:
            listbox_selected.insert(tk.END, os.path.basename(f))
    else:
        listbox_selected.insert(tk.END, "(Ningún archivo seleccionado)")

def on_enter(e):
    try:
        e.widget['background'] = BUTTON_HOVER_COLOR
    except Exception:
        pass

def on_leave(e):
    try:
        e.widget['background'] = BUTTON_COLOR
    except Exception:
        pass


def on_enter_alert(e):
    try:
        e.widget['background'] = BUTTON_ALERT_ACTIVE
    except Exception:
        pass


def on_leave_alert(e):
    try:
        e.widget['background'] = BUTTON_ALERT_COLOR
    except Exception:
        pass


def make_button(parent, text, command, is_alert=False):
    bg = BUTTON_ALERT_COLOR if is_alert else BUTTON_COLOR
    active_bg = BUTTON_ALERT_ACTIVE if is_alert else BUTTON_ACTIVE_COLOR
    border = BUTTON_BORDER_ALERT if is_alert else BUTTON_BORDER
    btn = tk.Button(
        parent,
        text=text,
        command=command,
        bg=bg,
        fg=FG_COLOR,
        activebackground=active_bg,
        activeforeground=FG_COLOR,
        bd=1,
        relief='solid',
        font=(FONT_FAMILY, 10, 'bold'),
        padx=8,
        pady=7,
        highlightthickness=1,
        highlightbackground=border,
        highlightcolor=border,
        cursor='hand2'
    )
    if is_alert:
        btn.bind('<Enter>', on_enter_alert)
        btn.bind('<Leave>', on_leave_alert)
    else:
        btn.bind('<Enter>', on_enter)
        btn.bind('<Leave>', on_leave)
    themed_buttons.append((btn, is_alert))
    return btn


def apply_theme(theme_name):
    set_theme_values(theme_name)
    theme = THEMES[theme_name]

    ventana.configure(bg=BG_COLOR)
    style.configure("TFrame", background=BG_COLOR)
    style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL))
    style.configure(
        "TButton",
        background=BUTTON_COLOR,
        foreground=FG_COLOR,
        font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
        borderwidth=0,
        relief="flat",
        padding=10
    )
    style.map(
        "TButton",
        background=[('active', BUTTON_HOVER_COLOR), ('pressed', ACCENT_COLOR)],
        foreground=[('pressed', BUTTON_COLOR), ('active', FG_COLOR)]
    )

    main_frame.configure(style="TFrame")
    frame_top.config(bg=BG_COLOR)
    top_actions.config(bg=BG_COLOR)
    title_label.config(bg=BG_COLOR, fg=ACCENT_COLOR)
    subtitle_label.config(bg=BG_COLOR, fg=MUTED_TEXT)
    theme_switch.config(bg=BG_COLOR, fg=MUTED_TEXT, activebackground=BG_COLOR, activeforeground=FG_COLOR, selectcolor=BG_COLOR)

    grid_frame.config(bg=BG_COLOR)
    left.config(bg=PANEL_COLOR, highlightbackground=BUTTON_BORDER)
    right.config(bg=PANEL_ALT_COLOR, highlightbackground=BUTTON_BORDER)
    left_title.config(bg=PANEL_COLOR, fg=FG_COLOR)
    listbox_frame_left.config(bg=PANEL_COLOR)
    btns_left.config(bg=PANEL_COLOR)
    actions_frame.config(bg=PANEL_ALT_COLOR)
    actions_label.config(bg=PANEL_ALT_COLOR, fg=FG_COLOR)
    contrasena_frame.config(bg=PANEL_ALT_COLOR)
    contrasena_label.config(bg=PANEL_ALT_COLOR, fg=MUTED_TEXT)
    output_frame.config(bg=PANEL_ALT_COLOR)
    sel_btn_frame.config(bg=BG_COLOR)
    resultados_label.config(bg=PANEL_ALT_COLOR, fg=FG_COLOR)
    resultado_frame.config(bg=PANEL_ALT_COLOR)

    listbox_selected.config(
        bg=theme["LISTBOX_BG"],
        fg=FG_COLOR,
        selectbackground=ACCENT_COLOR,
        selectforeground=theme["LISTBOX_SELECT_FG"]
    )
    contrasena_entry.config(bg=BUTTON_COLOR, fg=FG_COLOR, insertbackground=FG_COLOR)
    resultado_text.config(bg=theme["TEXT_BG"], fg=theme["TEXT_FG"], insertbackground=FG_COLOR)

    for btn, is_alert in themed_buttons:
        if is_alert:
            btn.config(
                bg=BUTTON_ALERT_COLOR,
                fg=FG_COLOR,
                activebackground=BUTTON_ALERT_ACTIVE,
                activeforeground=FG_COLOR,
                highlightbackground=BUTTON_BORDER_ALERT,
                highlightcolor=BUTTON_BORDER_ALERT,
            )
        else:
            btn.config(
                bg=BUTTON_COLOR,
                fg=FG_COLOR,
                activebackground=BUTTON_ACTIVE_COLOR,
                activeforeground=FG_COLOR,
                highlightbackground=BUTTON_BORDER,
                highlightcolor=BUTTON_BORDER,
            )

    style.configure(
        "green.Horizontal.TProgressbar",
        troughcolor=theme["PROGRESS_TROUGH"],
        background=ACCENT_COLOR,
        thickness=20
    )


def open_chat_app():
    if not os.path.exists(CHAT_SCRIPT):
        messagebox.showerror("Archivo faltante", f"No se encontro: {CHAT_SCRIPT}")
        return
    subprocess.Popen([sys.executable, CHAT_SCRIPT], cwd=APP_DIR)
    ventana.destroy()


def exit_app():
    ventana.destroy()


def toggle_theme():
    selected = "dark" if theme_var.get() else "light"
    apply_theme(selected)

try:
    ventana = tk.Tk()
except tk.TclError:
    print("No se pudo abrir la interfaz grafica. Verifica que tengas una sesion de escritorio activa.")
    sys.exit(1)
ventana.title("F3NIX Toolkit")
ventana.configure(bg=BG_COLOR)
ventana.attributes("-fullscreen", True)

# --- Style Configuration ---
style = ttk.Style()
style.theme_use('clam') # A more modern theme

style.configure("TFrame", background=BG_COLOR)
style.configure("TLabel", background=BG_COLOR, foreground=FG_COLOR, font=(FONT_FAMILY, FONT_SIZE_NORMAL))
style.configure("TButton",
    background=BUTTON_COLOR,
    foreground=FG_COLOR,
    font=(FONT_FAMILY, FONT_SIZE_NORMAL, "bold"),
    borderwidth=0,
    relief="flat",
    padding=10)
style.map("TButton",
    background=[('active', BUTTON_HOVER_COLOR), ('pressed', ACCENT_COLOR)],
    foreground=[('pressed', BUTTON_COLOR), ('active', FG_COLOR)])

# --- Main Frame ---
main_frame = ttk.Frame(ventana, padding=10)
main_frame.pack(fill='both', expand=True)

# Título
frame_top = tk.Frame(main_frame, bg=BG_COLOR)
frame_top.pack(fill='x')
theme_var = tk.BooleanVar(value=True)

title_label = tk.Label(
    frame_top,
    text='F3NIX TOOLKIT',
    bg=BG_COLOR,
    fg=ACCENT_COLOR,
    font=(FONT_FAMILY, 22, 'bold')
)
title_label.pack(anchor='w')
subtitle_label = tk.Label(
    frame_top,
    text='Herramientas de red, archivos, metadatos y cifrado',
    bg=BG_COLOR,
    fg=MUTED_TEXT,
    font=(FONT_FAMILY, 10)
)
subtitle_label.pack(anchor='w', pady=(0, 8))
theme_switch = tk.Checkbutton(
    frame_top,
    text="Modo oscuro",
    variable=theme_var,
    command=toggle_theme,
    bg=BG_COLOR,
    fg=MUTED_TEXT,
    activebackground=BG_COLOR,
    activeforeground=FG_COLOR,
    selectcolor=BG_COLOR,
    font=(FONT_FAMILY, 10),
    cursor='hand2'
)
theme_switch.pack(anchor='e', pady=(0, 6))

top_actions = tk.Frame(frame_top, bg=BG_COLOR)
top_actions.pack(anchor='e', pady=(0, 4))
btn_open_chat = make_button(top_actions, 'Ir a Chat', open_chat_app)
btn_open_chat.pack(side='left', padx=(0, 6))
btn_exit_main = make_button(top_actions, 'Salir', exit_app, is_alert=True)
btn_exit_main.pack(side='left')

# Grid principal
grid_frame = tk.Frame(main_frame, bg=BG_COLOR)
grid_frame.pack(expand=True, fill='both')
grid_frame.columnconfigure(1, weight=1)

# --- Layout: izquierda (lista + acciones principales) y derecha (acciones y resultado) ---
left = tk.Frame(grid_frame, bg=PANEL_COLOR, bd=0, highlightthickness=1, highlightbackground=BUTTON_BORDER)
left.grid(row=0, column=0, sticky='nsw', padx=(0,12), pady=4)
left.grid_rowconfigure(1, weight=3)
left.grid_rowconfigure(2, weight=1)
left.grid_columnconfigure(0, weight=1)

right = tk.Frame(grid_frame, bg=PANEL_ALT_COLOR, bd=0, highlightthickness=1, highlightbackground=BUTTON_BORDER)
right.grid(row=0, column=1, sticky='nsew')
grid_frame.columnconfigure(1, weight=1)

# Left: archivos seleccionados y botones principales
left_title = tk.Label(left, text='Archivos Seleccionados', bg=PANEL_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 11, 'bold'))
left_title.grid(row=0, column=0, sticky='w', padx=10, pady=(10, 4))
listbox_frame_left = tk.Frame(left, bg=PANEL_COLOR)
listbox_frame_left.grid(row=1, column=0, sticky='nsew', padx=10, pady=(2,6))
listbox_selected = tk.Listbox(
    listbox_frame_left,
    height=7,
    bg="#0F1A22",
    fg=FG_COLOR,
    selectbackground=ACCENT_COLOR,
    selectforeground="#0A1116",
    bd=0,
    relief='flat',
    font=(FONT_FAMILY, 10),
    activestyle='none'
)
listbox_selected.pack(side='left', fill='both', expand=True)
scroll_left = ttk.Scrollbar(listbox_frame_left, orient='vertical', command=listbox_selected.yview)
scroll_left.pack(side='right', fill='y')
listbox_selected.config(yscrollcommand=scroll_left.set)

btns_left = tk.Frame(left, bg=PANEL_COLOR)
btns_left.grid(row=2, column=0, sticky='new', padx=10, pady=(0,10))

agregar_btn = make_button(btns_left, 'Agregar Archivo', agregar_archivo)
agregar_btn.pack(fill='x', pady=2)

generar_btn = make_button(btns_left, 'Generar Resultado', generar_resultado)
generar_btn.pack(fill='x', pady=2)

# Right: acciones
actions_frame = tk.Frame(right, bg=PANEL_ALT_COLOR)
actions_frame.pack(fill='x', padx=10, pady=(10, 6))
actions_label = tk.Label(actions_frame, text='Acciones', bg=PANEL_ALT_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 11, 'bold'))
actions_label.pack(anchor='w', pady=(0,6))

escanear_arp_button = make_button(actions_frame, 'ARP Scan', escanear_arp)
escanear_arp_button.pack(fill='x', pady=3)

velocidad_button = make_button(actions_frame, 'Velocidad', medir_velocidad)
velocidad_button.pack(fill='x', pady=3)

mapa_button = make_button(actions_frame, 'IP y Mapa', obtener_ip_y_abrir_mapa)
mapa_button.pack(fill='x', pady=3)

gps_button = make_button(actions_frame, 'GPS Imagen', buscar_archivo_y_abrir_mapa)
gps_button.pack(fill='x', pady=3)

encrypt_button = make_button(actions_frame, 'Cifrar', encrypt_folder)
encrypt_button.pack(fill='x', pady=3)

decrypt_button = make_button(actions_frame, 'Descifrar', decrypt_folder)
decrypt_button.pack(fill='x', pady=3)

# Borrar metadatos en acciones a la derecha (alert style)
borrar_metadatos_button = make_button(actions_frame, 'Borrar Metadata', elegir_y_borrar_metadatos, is_alert=True)
borrar_metadatos_button.pack(fill='x', pady=(6, 2))

# --- Special Widgets ---
# Sudo password entry (en la columna derecha dentro de actions_frame)
contrasena_frame = tk.Frame(actions_frame, bg=PANEL_ALT_COLOR)
contrasena_frame.pack(fill='x', pady=(6,4))
contrasena_label = tk.Label(contrasena_frame, text="Sudo:", bg=PANEL_ALT_COLOR, fg=MUTED_TEXT, font=(FONT_FAMILY, 10, 'bold'))
contrasena_label.pack(side="left", padx=(0, 5))
contrasena_entry = tk.Entry(
    contrasena_frame,
    show="*",
    bg=BUTTON_COLOR,
    fg=FG_COLOR,
    font=(FONT_FAMILY, 10),
    relief="flat",
    insertbackground=FG_COLOR
)
contrasena_entry.pack(side="left", expand=True, fill="x")


# --- Output & Status Area (derecha) ---
output_frame = tk.Frame(right, bg=PANEL_ALT_COLOR)
output_frame.pack(expand=True, fill="both", padx=10, pady=(4, 10))

archivos_seleccionados = []

# Small action buttons for selection
sel_btn_frame = tk.Frame(output_frame, bg=BG_COLOR)
sel_btn_frame.pack(fill='x', pady=(3,0))
open_sel_btn = make_button(sel_btn_frame, 'Abrir', lambda: open_selected_file())
open_sel_btn.pack(side='left', padx=3)
del_sel_btn = make_button(sel_btn_frame, 'Eliminar', lambda: delete_selected_file(), is_alert=True)
del_sel_btn.pack(side='left', padx=3)

resultados_label = tk.Label(output_frame, text='Resultados', bg=PANEL_ALT_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 11, 'bold'))
resultados_label.pack(anchor='w', pady=(8,2))
resultado_frame = tk.Frame(output_frame, bg=PANEL_ALT_COLOR)
resultado_frame.pack(fill='both', expand=True, pady=(2,0))

resultado_text = tk.Text(
    resultado_frame,
    height=10,
    wrap='word',
    bg='#0E1A22',
    fg='#D9F0FF',
    bd=0,
    relief='flat',
    font=(FONT_FAMILY, 10),
    insertbackground=FG_COLOR
)
resultado_text.pack(side='left', fill='both', expand=True)
resultado_scroll = ttk.Scrollbar(resultado_frame, orient='vertical', command=resultado_text.yview)
resultado_scroll.pack(side='right', fill='y')
resultado_text.config(yscrollcommand=resultado_scroll.set, state='disabled')

# Crear estilo personalizado
style.configure("green.Horizontal.TProgressbar",
                troughcolor="#13222C",
                background=ACCENT_COLOR,
                thickness=20)            # grosor de la barra (opcional)
                
# Asignar estilo a tu progress bar
progress_bar = ttk.Progressbar(output_frame, orient="horizontal", length=200, mode="indeterminate", style="green.Horizontal.TProgressbar")
progress_bar.pack_forget()

# --- Helpers for selection actions ---
def open_path_in_system(path: str):
    if sys.platform.startswith("win"):
        os.startfile(path)
        return
    if sys.platform == "darwin":
        subprocess.Popen(["open", path])
        return
    subprocess.Popen(["xdg-open", path])


def open_selected_file():
    try:
        sel = listbox_selected.curselection()
        if not sel:
            messagebox.showinfo("Seleccionar", "Seleccione un archivo en la lista.")
            return
        path = archivos_seleccionados[sel[0]]
        if path:
            open_path_in_system(path)
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo abrir el archivo: {e}")


def delete_selected_file():
    try:
        sel = listbox_selected.curselection()
        if not sel:
            messagebox.showinfo("Seleccionar", "Seleccione un archivo para eliminar.")
            return
        idx = sel[0]
        archivos_seleccionados.pop(idx)
        update_selected_files_label()
    except Exception as e:
        messagebox.showerror("Error", f"No se pudo eliminar el archivo: {e}")

apply_theme(CURRENT_THEME)

ventana.mainloop()
