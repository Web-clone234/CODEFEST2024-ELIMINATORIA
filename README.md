![Codeneas](https://github.com/user-attachments/assets/ece2a661-8f6a-4326-9f02-7af6eb25946e)


# CODEFEST AD ASTRA 2024 - FASE FINAL: Solución de Cifrado para Comunicación Satelital

## Estructura de Directorios

A continuación, se presenta la estrcutura del repositorio junto con el contenido y descripción decada uno de los archivos y directorios existentes

```
├── cryptopp                    # Librería Crypto++
│   ├── *.h                     # Archivos de encabezado de Crypto++
│   ├── *.cpp                   # Archivos fuente de Crypto++
│   └── ...                     # Otros archivos para el funcionamiento de la librería
├── images                      # Carpeta con imagenes de prueba
│   ├── PIA05566.tif            # Imagen de prueba 5MB
├── media                       # Contenido audiovisual asociado a la solución
│   ├── videoExplicativo.mp4    # Video explicativo de la solución preliminar propuesta
├── documentacion.pdf           # Documentación detallada de la solución propuesta
├── main.cpp                    # Archivo principal del programa
├── Makefile                    # Script de compilación
├── LICENSE                     # Archivo de licencia del proyecto
├── README.md                   # Archivo README del proyecto
```

## Pre-requisitos

Antes de comenzar, asegúrate de tener las herramientas necesarias instaladas. Puedes acceder a estas siguiendo los comandos específicados para tu sistema operativo:

### Linux

Abre una terminal y ejecuta los siguientes comandos.

```
sudo apt update
sudo apt install build-essential
```

### Windows

#### Descarga el instalador de MSYS2

Disponible en este enlace: [MSYS2 Installer](https://www.msys2.org/)

#### Ejecuta el instalador

Sigue las instrucciones para instalar MSYS2. Después de la instalación, deberías tener una nueva terminal shell de MSYS2.

#### Configura las herramientas de instalación

En la terminal de MSYS2, ejecuta el comando:

```
pacman -S --needed base-devel mingw-w64-ucrt-x86_64-toolchain
```

Acepta el número predeterminado de paquetes en el toolchain presionando enter e ingresa `Y` para continuar con la instalación.

#### Añade el directorio bin de MinGW-w64 a las variables de entorno de Windows

Si utilizaste las configuraciones por defecto, debes añadir `C:\msys64\ucrt64\bin` a la variable Path.

#### Comprueba la instalación de MinGW

Abre una nueva terminal y ejecuta los comandos:

```
gcc --version
g++ --version
gdb --version
```

Si todo se instaló correctamente, deberías ver la versión correspondiente de cada herramienta.

## Uso

Úbicate en la carpeta raiz del repositorio y ejecuta los siguientes tomando desde la terminal de tu dispositivo:

### Linux

Para compilar el programa:

```
make
```

> Al ejecutar este comando por primera vez, se compilará la librería estática de Crypto++, creando los object files que serán vinculados con el programa final. Crypto++ es una librería muy completa con muchos módulos, por lo que esto puede tomar unos minutos. Compilar de nuevo el programa no compilará de nuevo la librería.
> <br/>

Para utilizar el programa, sigue el patrón: `./main` `<operation>` `'<input_path>'` `'<output_path>'`, donde:

- `<operation>`: `encrypt` o `decrypt`
- `<input_path>`: La ruta de la imagen de entrada
- `<output_path>`: La ruta de la imagen de salida

Un ejemplo del comando para encriptar una imagen es:

```
./main encrypt '/home/user/Pictures/Linux_logo.tiff' '/home/user/Pictures/encrypted.tiff'
```

> El proceso siempre se debe ejecutar de forma secuencial. Esto quiere decir que al encriptar una imagen la siguiente operación siempre debe ser desencriptarla.

### Windows

Para compilar el programa:

```
mingw32-make
```

> Al ejecutar este comando por primera vez, se compilará la librería estática de Crypto++, creando los object files que serán vinculados con el programa final. Crypto++ es una librería muy completa con muchos módulos, por lo que esto puede tomar unos minutos. Compilar de nuevo el programa no compilará de nuevo la librería.
> <br/>

Para utilizar el programa, sigue el patrón: `main.exe` `<operation>` `"<input_path>"` `"<output_path>"`, donde:

- `<operation>`: `encrypt` o `decrypt`
- `<input_path>`: La ruta de la imagen de entrada
- `<output_path>`: La ruta de la imagen de salida

Un ejemplo del comando para encriptar una imagen es:

```
main.exe encrypt "Test Images/PIA05566.tif" "encrypted.tiff"
```

> El proceso siempre se debe ejecutar de forma secuencial. Esto quiere decir que al encriptar una imagen la siguiente operación siempre debe ser desencriptarla.

## Autores

- Nicolás Bedoya Figueroa - [`nicobf56`](https://github.com/nicobf56)
- Manuela Pacheco Malagón - [`itsmemanuu`](https://github.com/itsmemanuu)
- Nicolás Rozo Fajardo - [`MrCheesyBurgerU`](https://github.com/MrCheesyBurgerU)
- Luis Felipe Torres Galvis - [`Luisfetoga2`](https://github.com/Luisfetoga2)

## Licencia

Este proyecto está bajo la GNU General Public License. Para más detalles, consulta el archivo [`LICENSE`](https://github.com/CODENEAS/CODEFEST2024-ELIMINATORIA/blob/main/LICENSE).
