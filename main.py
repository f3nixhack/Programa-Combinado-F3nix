#F3nix
import tkinter as tk
from tkinter import ttk, filedialog
import subprocess
import speedtest
import requests
import os

# Función para procesar un archivo
def procesar_archivo(archivo):
    palabras = set()
    with open(archivo, 'r', encoding='utf-8', errors='ignore') as file:
        for line in file:
            palabras.update(line.split())
    return palabras

# Función para agregar archivos
def agregar_archivo():
    archivo = filedialog.askopenfilename(filetypes=[("Archivos de texto", "*.txt")])
    if archivo:
        archivos_seleccionados.append(archivo)
        archivos_seleccionados_label.config(text="Archivos seleccionados:\n" + "\n".join(archivos_seleccionados))

# Función para generar el resultado
def generar_resultado():
    palabras_unicas = set()
    for archivo in archivos_seleccionados:
        palabras_unicas.update(procesar_archivo(archivo))
    
    resultado = 'resultado.txt'
    with open(resultado, 'w') as file:
        file.write('\n'.join(palabras_unicas))

    resultado_label.config(text=f'Se han creado {len(palabras_unicas)} palabras únicas en {resultado}')

# Función para realizar un escaneo ARP
def escanear_arp():
    try:
        # Obtener la contraseña del Entry
        contrasena = contrasena_entry.get()
        comando = f'sudo -S arp-scan --localnet'
        resultado_arp = subprocess.check_output(comando, shell=True, input=f'{contrasena}\n'.encode()).decode('utf-8')
        resultado_label.config(text=f'Resultado ARP Scan:\n{resultado_arp}')
    except subprocess.CalledProcessError as e:
        resultado_label.config(text=f'Error al ejecutar arp-scan: {e}')

# Función para medir la velocidad de internet
def medir_velocidad():
    st = speedtest.Speedtest()
    descarga = st.download() / 1024 / 1024
    subida = st.upload() / 1024 / 1024
    ping = st.results.ping
    resultado_label.config(text=f'Velocidad de Descarga: {descarga:.2f} Mbps\nVelocidad de Subida: {subida:.2f} Mbps\nPing: {ping} ms')

# Función para obtener la dirección IP y abrir Google Maps
def obtener_ip_y_abrir_mapa():
    try:
        ip = requests.get('https://ipinfo.io').text
        resultado_label.config(text=f'Dirección IP: {ip}')
        
        if ip:
            ip_info = requests.get(f'https://ipinfo.io/{ip}/json').json()
            if 'loc' in ip_info:
                lat, lon = ip_info['loc'].split(',')
                maps_url = f'https://www.google.com/maps/place/{lat},{lon}'
                subprocess.Popen(['xdg-open', maps_url])
    except requests.RequestException:
        resultado_label.config(text='Error al obtener la dirección IP.')

# Función para borrar metadatos de un archivo
def borrar_metadatos(archivo):
    try:
        subprocess.run(["exiftool", "-all=", archivo])
        resultado_label.config(text=f'Se han borrado los metadatos de {archivo}')
    except FileNotFoundError:
        resultado_label.config(text='ExifTool no está instalado. Por favor, instálelo para utilizar esta función.')

# Función para elegir archivo para borrar metadatos
def elegir_archivo_borrar_metadatos():
    archivo = filedialog.askopenfilename(filetypes=[("Todos los archivos", "*.*")])
    if archivo:
        borrar_metadatos_button.config(state="normal")
        archivos_seleccionados.append(archivo)
        archivos_seleccionados_label.config(text="Archivo seleccionado para borrar metadatos:\n" + archivo)

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Programa Combinado F3NIX")

# Lista (array) para almacenar los archivos seleccionados
archivos_seleccionados = []

# Botones
style = ttk.Style()
style.configure('Boton3D.TButton', relief='raised', borderwidth=5, background='black', foreground='green')
agregar_button = ttk.Button(ventana, text="Agregar Archivo", command=agregar_archivo, style='Boton3D.TButton')
agregar_button.pack()

generar_button = ttk.Button(ventana, text="Generar Resultado", command=generar_resultado, style='Boton3D.TButton')
generar_button.pack()

# Entry para ingresar la contraseña de sudo
contrasena_entry = tk.Entry(ventana, show="*", bg='black', fg='green')
contrasena_entry.pack()

escanear_arp_button = ttk.Button(ventana, text="Escanear ARP", command=escanear_arp, style='Boton3D.TButton')
escanear_arp_button.pack()

velocidad_button = ttk.Button(ventana, text="Medir Velocidad de Internet", command=medir_velocidad, style='Boton3D.TButton')
velocidad_button.pack()

mapa_button = ttk.Button(ventana, text="Obtener IP y Abrir Mapa", command=obtener_ip_y_abrir_mapa, style='Boton3D.TButton')
mapa_button.pack()

# Botón para elegir archivo para borrar metadatos
elegir_archivo_borrar_metadatos_button = ttk.Button(ventana, text="Elegir Archivo para Borrar Metadatos", command=elegir_archivo_borrar_metadatos, style='Boton3D.TButton')
elegir_archivo_borrar_metadatos_button.pack()

# Botón para borrar metadatos
borrar_metadatos_button = ttk.Button(ventana, text="Borrar Metadatos", command=lambda: borrar_metadatos(archivos_seleccionados[0]), style='Boton3D.TButton', state="disabled")
borrar_metadatos_button.pack()

# Etiqueta para mostrar los archivos seleccionados
archivos_seleccionados_label = tk.Label(ventana, text="Archivos seleccionados:", bg='black', fg='green')
archivos_seleccionados_label.pack()

# Etiqueta para mostrar el resultado
resultado_label = tk.Label(ventana, text="", bg='black', fg='green')
resultado_label.pack()

ventana.configure(bg='black')  # Cambia el color de fondo de la ventana principal
ventana.mainloop()
