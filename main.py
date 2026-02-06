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
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# --- UI Configuration (tema oscuro estilo main.py) ---
BG_COLOR = "#0b0b0b"
FG_COLOR = "#E6F2FF"
ACCENT_COLOR = "#99E6FF"
BUTTON_COLOR = "#222222"
BUTTON_HOVER_COLOR = "#3a3a3a"
BUTTON_ACTIVE_COLOR = "#555555"
BUTTON_BORDER = "#333333"
# Red tones for destructive actions (oscuro)
RED_ACCENT = "#E53935"
BUTTON_ALERT_COLOR = "#7a1f1f"
BUTTON_ALERT_ACTIVE = "#a03333"
BUTTON_BORDER_ALERT = "#5b0f0f"
FONT_FAMILY = "Helvetica"
FONT_SIZE_NORMAL = 10
FONT_SIZE_LARGE = 13

# --- Core Functions ---

# Variable global para el widget de texto de resultados
resultado_text = None

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
    try:
        # 1. Comprimir la carpeta
        escribir_resultado(f"Comprimiendo {os.path.basename(folder_path)}...")
        ventana.update_idletasks()
        temp_archive = shutil.make_archive("temp_archive", 'zip', folder_path)

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
        temp_archive = "temp_archive_decrypted.zip"
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

ventana = tk.Tk()
ventana.title("F3NIX Toolkit")
ventana.configure(bg=BG_COLOR)
ventana.geometry("900x600") # Tamaño compacto

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
main_frame = ttk.Frame(ventana, padding=6)
main_frame.pack(fill='both', expand=True)

# Título
frame_top = ttk.Frame(main_frame, padding=(8, 8, 8, 4))
frame_top.pack(fill='x')
ttk.Label(frame_top, text='F3NIX TOOLKIT', font=(FONT_FAMILY, 18, 'bold'), foreground=ACCENT_COLOR).pack(anchor='w')

# Grid principal
grid_frame = ttk.Frame(main_frame)
grid_frame.pack(expand=True, fill='both')
grid_frame.columnconfigure(1, weight=1)

# --- Layout: izquierda (lista + acciones principales) y derecha (acciones y resultado) ---
left = ttk.Frame(grid_frame)
left.grid(row=0, column=0, sticky='nsw', padx=(0,12), pady=4)

right = ttk.Frame(grid_frame)
right.grid(row=0, column=1, sticky='nsew')
grid_frame.columnconfigure(1, weight=1)

# Left: archivos seleccionados y botones principales
ttk.Label(left, text='Archivos:').pack(anchor='w')
listbox_frame_left = ttk.Frame(left)
listbox_frame_left.pack(fill='both', expand=True, pady=(2,6))
listbox_selected = tk.Listbox(listbox_frame_left, height=6, bg='#111111', fg='#FFFFFF', bd=2, relief='sunken', font=(FONT_FAMILY, 9))
listbox_selected.pack(side='left', fill='both', expand=True)
scroll_left = ttk.Scrollbar(listbox_frame_left, orient='vertical', command=listbox_selected.yview)
scroll_left.pack(side='right', fill='y')
listbox_selected.config(yscrollcommand=scroll_left.set)

btns_left = ttk.Frame(left, padding=(0,2))
btns_left.pack(fill='x', pady=(0,0))

agregar_btn = tk.Button(btns_left, text='Agregar', command=agregar_archivo, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
agregar_btn.pack(fill='x', pady=2)
agregar_btn.bind('<Enter>', on_enter); agregar_btn.bind('<Leave>', on_leave)

generar_btn = tk.Button(btns_left, text='Generar', command=generar_resultado, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
generar_btn.pack(fill='x', pady=2)
generar_btn.bind('<Enter>', on_enter); generar_btn.bind('<Leave>', on_leave)

# Right: acciones
actions_frame = ttk.LabelFrame(right, text='Acciones', padding=6)
actions_frame.pack(fill='x')

escanear_arp_button = tk.Button(actions_frame, text='ARP Scan', command=escanear_arp, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
escanear_arp_button.pack(fill='x', pady=3)
escanear_arp_button.bind('<Enter>', on_enter); escanear_arp_button.bind('<Leave>', on_leave)

velocidad_button = tk.Button(actions_frame, text='Velocidad', command=medir_velocidad, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
velocidad_button.pack(fill='x', pady=3)
velocidad_button.bind('<Enter>', on_enter); velocidad_button.bind('<Leave>', on_leave)

mapa_button = tk.Button(actions_frame, text='IP y Mapa', command=obtener_ip_y_abrir_mapa, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
mapa_button.pack(fill='x', pady=3)
mapa_button.bind('<Enter>', on_enter); mapa_button.bind('<Leave>', on_leave)

gps_button = tk.Button(actions_frame, text='GPS Imagen', command=buscar_archivo_y_abrir_mapa, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
gps_button.pack(fill='x', pady=3)
gps_button.bind('<Enter>', on_enter); gps_button.bind('<Leave>', on_leave)

encrypt_button = tk.Button(actions_frame, text='Cifrar', command=encrypt_folder, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
encrypt_button.pack(fill='x', pady=3)
encrypt_button.bind('<Enter>', on_enter); encrypt_button.bind('<Leave>', on_leave)

decrypt_button = tk.Button(actions_frame, text='Descifrar', command=decrypt_folder, bg=BUTTON_COLOR, fg=FG_COLOR, bd=2, relief='raised', font=(FONT_FAMILY, 9), padx=2, pady=2)
decrypt_button.pack(fill='x', pady=3)
decrypt_button.bind('<Enter>', on_enter); decrypt_button.bind('<Leave>', on_leave)

# Borrar metadatos en acciones a la derecha (alert style)
alert_frame = tk.Frame(actions_frame, bg=BUTTON_BORDER_ALERT)
alert_frame.pack(fill='x', pady=(3,0))
borrar_metadatos_button = tk.Button(alert_frame, text='Borrar Metadata', command=elegir_y_borrar_metadatos, bg=BUTTON_ALERT_COLOR, fg=FG_COLOR, relief='raised', bd=2, activebackground=BUTTON_ALERT_ACTIVE, font=(FONT_FAMILY, 9, 'bold'), padx=2, pady=2)
borrar_metadatos_button.pack(fill='both', expand=True, padx=3, pady=3)
borrar_metadatos_button.bind('<Enter>', on_enter_alert); borrar_metadatos_button.bind('<Leave>', on_leave_alert)

# --- Special Widgets ---
# Sudo password entry (en la columna derecha dentro de actions_frame)
contrasena_frame = ttk.Frame(actions_frame)
contrasena_frame.pack(fill='x', pady=(4,4))
contrasena_label = ttk.Label(contrasena_frame, text="Sudo:")
contrasena_label.pack(side="left", padx=(0, 5))
contrasena_entry = tk.Entry(contrasena_frame, show="*", bg=BUTTON_COLOR, fg=FG_COLOR, font=(FONT_FAMILY, 9), relief="flat", insertbackground=FG_COLOR)
contrasena_entry.pack(side="left", expand=True, fill="x")


# --- Output & Status Area (derecha) ---
output_frame = ttk.Frame(right, padding="4")
output_frame.pack(expand=True, fill="both", pady=(3, 0))

archivos_seleccionados = []

# Small action buttons for selection
sel_btn_frame = tk.Frame(output_frame, bg=BG_COLOR)
sel_btn_frame.pack(fill='x', pady=(3,0))
open_sel_btn = tk.Button(sel_btn_frame, text='Abrir', command=lambda: open_selected_file(), bg=BUTTON_COLOR, fg=FG_COLOR, relief='raised', bd=2, font=(FONT_FAMILY, 9), padx=2, pady=1)
open_sel_btn.pack(side='left', padx=3)
open_sel_btn.bind('<Enter>', on_enter); open_sel_btn.bind('<Leave>', on_leave)
del_sel_btn = tk.Button(sel_btn_frame, text='Eliminar', command=lambda: delete_selected_file(), bg=BUTTON_ALERT_COLOR, fg=FG_COLOR, relief='raised', bd=2, font=(FONT_FAMILY, 9), padx=2, pady=1)
del_sel_btn.pack(side='left', padx=3)
del_sel_btn.bind('<Enter>', on_enter_alert); del_sel_btn.bind('<Leave>', on_leave_alert)

ttk.Label(output_frame, text='Resultados:').pack(anchor='w', pady=(4,2))
resultado_frame = ttk.Frame(output_frame)
resultado_frame.pack(fill='both', expand=True, pady=(2,0))

resultado_text = tk.Text(resultado_frame, height=10, wrap='word', bg='#050505', fg='#CFEFFD', bd=2, relief='sunken', font=(FONT_FAMILY, 9))
resultado_text.pack(side='left', fill='both', expand=True)
resultado_scroll = ttk.Scrollbar(resultado_frame, orient='vertical', command=resultado_text.yview)
resultado_scroll.pack(side='right', fill='y')
resultado_text.config(yscrollcommand=resultado_scroll.set, state='disabled')

# Crear estilo personalizado
style.configure("green.Horizontal.TProgressbar",
                troughcolor="#333333",  # color de fondo (gris oscuro)
                background="#76FF03",    # color de la barra llena (verde)
                thickness=20)            # grosor de la barra (opcional)
                
# Asignar estilo a tu progress bar
progress_bar = ttk.Progressbar(output_frame, orient="horizontal", length=200, mode="indeterminate", style="green.Horizontal.TProgressbar")
progress_bar.pack_forget()

# --- Helpers for selection actions ---
def open_selected_file():
    try:
        sel = listbox_selected.curselection()
        if not sel:
            messagebox.showinfo("Seleccionar", "Seleccione un archivo en la lista.")
            return
        path = archivos_seleccionados[sel[0]]
        if path:
            subprocess.Popen(['xdg-open', path])
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


ventana.mainloop()

