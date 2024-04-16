# Programa-Combinado-F3nix
Probado en linux

![Captura de pantalla_2024-04-14_20-07-07](https://github.com/f3nixhack/Programa-Combinado-F3nix/assets/50671074/0aadd104-68e7-4931-8685-9fcb4b204789)

Este código es un programa de interfaz gráfica de usuario (GUI) en Python utilizando la biblioteca `tkinter`. Te explicaré cada parte del código:

1. **Importación de bibliotecas**: 
   - `tkinter`: Es la biblioteca estándar de Python para crear interfaces gráficas de usuario.
   - `filedialog`: Proporciona funciones para trabajar con cuadros de diálogo para abrir y guardar archivos.
   - `subprocess`: Permite crear nuevos procesos, conectar con sus tuberías de entrada/salida/error, y obtener sus códigos de retorno.
   - `speedtest`: Es una biblioteca para medir la velocidad de la conexión a Internet.
   - `requests`: Se utiliza para realizar solicitudes HTTP en Python.

2. **Definición de funciones**:
   - `procesar_archivo(archivo)`: Lee un archivo de texto y devuelve un conjunto de palabras únicas.
   - `agregar_archivo()`: Abre un cuadro de diálogo para seleccionar un archivo de texto y lo agrega a una lista de archivos seleccionados.
   - `generar_resultado()`: Procesa los archivos seleccionados y guarda las palabras únicas en un archivo de texto llamado 'resultado.txt'.
   - `escanear_arp()`: Realiza un escaneo ARP en la red local utilizando el comando `arp-scan`. Solicita la contraseña de sudo mediante un cuadro de entrada.
   - `medir_velocidad()`: Mide la velocidad de descarga y subida de Internet, así como el ping utilizando la biblioteca `speedtest`.
   - `obtener_ip_y_abrir_mapa()`: Obtiene la dirección IP del dispositivo y abre Google Maps en el navegador web con la ubicación correspondiente.

3. **Creación de la ventana principal (`ventana`)**:
   - Se crea una ventana principal utilizando `tkinter`.
   - Se establece el título de la ventana como "Programa Combinado F3NIX".

4. **Elementos de la interfaz gráfica**:
   - Se crean botones (`Button`) para agregar archivos, generar resultados, escanear ARP, medir la velocidad de Internet y abrir Google Maps.
   - Se crea un campo de entrada (`Entry`) para ingresar la contraseña de sudo.
   - Se crean etiquetas (`Label`) para mostrar los archivos seleccionados y los resultados.

5. **Ejecución del bucle principal**:
   - Se inicia el bucle principal (`mainloop()`) de la ventana, lo que permite que la interfaz gráfica sea interactiva y responda a las acciones del usuario.

En resumen, este programa combina varias funcionalidades como procesamiento de archivos de texto, escaneo de red, medición de velocidad de Internet y obtención de la dirección IP del dispositivo, todo dentro de una interfaz gráfica de usuario.
