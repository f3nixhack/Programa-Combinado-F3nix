# Programa-Combinado-F3nix
![WhatsApp Image 2026-02-06 at 17 42 54](https://github.com/user-attachments/assets/8e98971f-d25b-484f-a96f-bbe56f4fed38)

Probado en linux
Excelente actualización. Esto **ya no es solo un refactor**, es una **evolución clara del producto**.
Te dejo **la descripción nueva**, más **un resumen de cambios respecto a la versión anterior**, listo para README, publicación o release.

---

## 🔥 F3NIX TOOLKIT – Versión actualizada

**F3NIX Toolkit** es una **suite avanzada de utilidades técnicas y de seguridad** desarrollada en Python con interfaz gráfica moderna. Integra análisis de red, privacidad, cifrado fuerte, geolocalización y procesamiento de archivos en una sola aplicación, orientada a **usuarios técnicos, seguridad informática y análisis digital**.

### 🧩 Funcionalidades principales

#### 📁 Gestión y análisis de archivos

* Selección múltiple de archivos (texto e imágenes).
* Generación de listas de **palabras únicas** desde múltiples archivos `.txt`.
* Panel lateral con **lista interactiva**:

  * Abrir archivos
  * Eliminar de la lista
* Área de resultados **desplazable y persistente**.

#### 🌐 Red y conectividad

* **ARP Scan** de la red local con ejecución controlada por sudo.
* **Test de velocidad de Internet** en segundo plano:

  * Descarga, subida y ping
  * Información del servidor, ISP e IP del cliente
  * Barra de progreso visual sin bloquear la interfaz.
* Obtención de **IP pública** y apertura automática de su ubicación aproximada en Google Maps.

#### 🗺️ Metadatos y geolocalización

* Lectura de **metadatos EXIF y GPS** en imágenes.
* Apertura directa de Google Maps desde coordenadas GPS.
* **Eliminación completa de metadatos** mediante ExifTool (acción destacada como destructiva).

#### 🔐 Cifrado fuerte de carpetas (nuevo núcleo de seguridad)

* Cifrado y descifrado de carpetas completas usando:

  * **PBKDF2 + SHA-256**
  * **Fernet (AES simétrico autenticado)**
* Protección por contraseña definida por el usuario.
* Formato propio `.f3nixcrypt`.
* Limpieza automática de archivos temporales.
* Manejo seguro de errores (contraseña incorrecta, archivo corrupto).

#### 🎨 Interfaz gráfica moderna

* Tema oscuro personalizado tipo **toolkit profesional**.
* Diseño en dos paneles:

  * Izquierda: archivos y acciones básicas.
  * Derecha: acciones avanzadas y resultados.
* Botones con:

  * Hover
  * Estados activos
  * Colores diferenciados para acciones destructivas.
* Operaciones pesadas ejecutadas en **hilos** para no congelar la UI.

---

## 🚀 Principales mejoras respecto a la versión anterior

✔ Interfaz completamente rediseñada (más clara, moderna y usable)
✔ Área de resultados con scroll y salida estructurada
✔ Multithreading (speedtest sin congelar la app)
✔ Cifrado **real** con criptografía moderna (ya no GPG externo)
✔ Eliminación segura y explícita de metadatos
✔ Gestión visual de archivos seleccionados
✔ Mejor manejo de errores y validaciones
✔ Código más modular y mantenible

---

## 🎯 Perfil del proyecto

**F3NIX Toolkit** es ahora una herramienta:

* Más **profesional**
* Más **segura**
* Más **usable**
* Más **orientada a seguridad y privacidad**

Ideal para:

* Laboratorios personales
* Usuarios Linux técnicos
* Aprendizaje de ciberseguridad
* Análisis básico forense y de red
