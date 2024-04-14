#F3nix
import tkinter as tk
from tkinter import filedialog
import subprocess
import speedtest
import requests

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

# Crear la ventana principal
ventana = tk.Tk()
ventana.title("Programa Combinado F3NIX")

# Lista (array) para almacenar los archivos seleccionados
archivos_seleccionados = []

# Botones
agregar_button = tk.Button(ventana, text="Agregar Archivo", command=agregar_archivo)
agregar_button.pack()

generar_button = tk.Button(ventana, text="Generar Resultado", command=generar_resultado)
generar_button.pack()

# Entry para ingresar la contraseña de sudo
contrasena_entry = tk.Entry(ventana, show="*")
contrasena_entry.pack()

escanear_arp_button = tk.Button(ventana, text="Escanear ARP", command=escanear_arp)
escanear_arp_button.pack()

velocidad_button = tk.Button(ventana, text="Medir Velocidad de Internet", command=medir_velocidad)
velocidad_button.pack()

mapa_button = tk.Button(ventana, text="Obtener IP y Abrir Mapa", command=obtener_ip_y_abrir_mapa)
mapa_button.pack()

# Etiqueta para mostrar los archivos seleccionados
archivos_seleccionados_label = tk.Label(ventana, text="Archivos seleccionados:")
archivos_seleccionados_label.pack()

# Etiqueta para mostrar el resultado
resultado_label = tk.Label(ventana, text="")
resultado_label.pack()

ventana.mainloop()
