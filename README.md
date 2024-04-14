# Programa-Combinado-F3nix
![Captura de pantalla_2024-04-14_20-07-07](https://github.com/f3nixhack/Programa-Combinado-F3nix/assets/50671074/0aadd104-68e7-4931-8685-9fcb4b204789)

Este programa es una aplicación de escritorio construida con la biblioteca Tkinter en Python. Su objetivo es ofrecer una serie de funciones combinadas que incluyen:

1. **Agregar Archivo**: Permite al usuario seleccionar archivos de texto.

2. **Generar Resultado**: Procesa los archivos seleccionados para encontrar palabras únicas y guarda estos resultados en un archivo llamado `resultado.txt`.

3. **Escanear ARP**: Realiza un escaneo ARP en la red local y muestra los resultados.

4. **Medir Velocidad de Internet**: Utiliza la biblioteca `speedtest` para medir la velocidad de descarga, velocidad de subida y ping de la conexión a Internet.

5. **Obtener IP y Abrir Mapa**: Obtiene la dirección IP pública del usuario utilizando la API de ipinfo.io y luego abre Google Maps en el navegador web predeterminado, mostrando la ubicación correspondiente a esa dirección IP.

Ahora, voy a explicar cada parte del código:

- Se importan las bibliotecas necesarias: `tkinter` para la interfaz gráfica, `filedialog` para el cuadro de diálogo de selección de archivo, `subprocess` para ejecutar comandos del sistema, `speedtest` para medir la velocidad de Internet y `requests` para hacer solicitudes HTTP.

- Se definen varias funciones para las distintas acciones que puede realizar el programa, como agregar archivo, generar resultado, escanear ARP, medir la velocidad de Internet y obtener la IP y abrir mapa.

- Se crea la ventana principal de la aplicación con Tkinter.

- Se crean botones para cada función definida, cada uno asociado con su respectiva función.

- Se crean etiquetas para mostrar información al usuario, como los archivos seleccionados y los resultados de las operaciones.

- Finalmente, se llama al método `mainloop()` para que la ventana de la aplicación esté en funcionamiento y esperando interacciones del usuario.

En resumen, este programa proporciona una interfaz gráfica simple para realizar varias tareas relacionadas con archivos, redes y mediciones de Internet.
