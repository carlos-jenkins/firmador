Firmador
========

Firmador es una herramienta que permite comunicar navegadores web con
dispositivos de Firma Digital. Los sitios web pueden solicitar al firmador
un certificado del dispositivo y solicitar firmar un resumen criptográfico
con la clave privada del dispositivo asociado al certificado.

El proyecto está diseñado para uso con el sistema de Firma Digital de
Costa Rica, aunque podría resultar útil para otros países.


Funcionamiento
--------------

El mecanismo funciona mediante un servicio de escritorio con un servicio web
que escucha en la dirección local en un puerto específico. Un sitio web trata
de conectar a esta dirección local y se comunica mediante peticiones a rutas
específicas, tratándose de un servicio RESTful, enviando y recibiendo
estructuras en formato JSON.

El servicio de escritorio solamente se encarga de firmar los resúmenes
criptográficos. El sitio web remoto, que no forma parte de este proyecto, es el
encargado del resto de la operación, por ejemplo, extraer el resumen de un
documento, hacer las llamadas al servicio de escritorio, recibir el resumen y
ensamblar la firma en el documento. Se podría realizar una demostración propia
eventualmente, aunque por ahora las
[demostraciones de DSS](https://github.com/esig/dss-demonstrations)
y su documentación son útiles para probar la funcionalidad del lado del
servidor. Puesto que el ensamblado de la firma no lo realiza el firmador, es
agnóstico en cuanto al tipo de documento y nivel firma a generar, encargándose
de esta tarea el servicio web remoto, sin importar si se trata de XAdES, CAdES,
PAdES, ASIC-E (para OpenDocument y Office Open XML), etc.

La API REST de comunicación con el servidor es compatible con la utilizada
por el proyecto
[DSS](https://ec.europa.eu/cefdigital/wiki/pages/viewpage.action?pageId=46992515)
en su demostración web de firma de documentos, específicamente trata de
reemplazar la herramienta
[NexU](http://nowina.lu/nexu/) pero sin requerir Java en el escritorio,
permitiendo que la herramienta sea más ligera de dependencias, menor tamaño y
menor consumo de memoria RAM.

Firmador es compatible con GNU/Linux, macOS y Windows.


Tecnologías usadas
------------------

* [GnuTLS](https://gnutls.org/) compilado con p11-kit, que incluye todos los
  servicios criptográficos necesarios para comunicarse con el dispositivo.

* [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/) para el servicio
  web de escritorio.

* [RapidJSON](http://rapidjson.org/) para el manejo de estructuras JSON.

* [wxWidgets](https://wxwidgets.org/) como interfaz gráfica multiplataforma
  nativa.


Instalación
-----------

### Requerimientos

* Compilador de lenguaje C++.
* Cabeceras de desarrollo de GnuTLS, libmicrohttpd, RapidJSON y wxWidgets.
* Autoconf, Automake y pkg-config

En Fedora, Red Hat Enterprise Linux (con EPEL) y CentOS (con EPEL) se pueden
instalar las dependencias con:

    # dnf -y install git-core gcc-c++ automake gnutls-devel libmicrohttpd-devel wxGTK3-devel rapidjson-devel

En el caso de Red Hat Enterprise Linux y CentOS reemplazar `dnf` con `yum`.

En Debian y Ubuntu se pueden instalar las dependencias con:

    # apt -y install git-core g++ automake pkg-config libgnutls28-dev libmicrohttpd-dev libwxgtk3.0-dev rapidjson-dev

En SUSE Linux Enterprise Server 12 (con el Software Development Kit) se pueden
instalar las dependencias con:

    # zypper install -y git-core gcc-c++ automake pkg-config libgnutls-devel libmicrohttpd-devel wxWidgets-devel

SUSE Linux Enterprise Server 12 requiere instalar `rapidjson` aparte, ya sea
copiando la carpeta de cabeceras o mediante paquete externo.

En macOS se pueden instalar las dependencias con [Homebrew](https://brew.sh/):

    $ brew install wxmac gnutls libmicrohttpd rapidjson automake autoconf pkg-config

En Windows se pueden instalar las dependencias con
[MSYS2](http://www.msys2.org/) en la consola MSYS2 MinGW 32-bit con:

    $ pacman -Su --noconfirm git make autoconf automake mingw-w64-i686-{pkg-config,make,gcc,wxWidgets,gnutls,rapidjson}


### Compilación

Si se está instalando desde el repositorio git, ejecutar la primera vez:

    git clone https://github.com/fdelapena/firmador.git
    cd firmador
    autoreconf -i

Para compilar:

    ./configure
    make


### Binarios precompilados para Windows

Se puede descargar desde mi servidor de integración continua una
[versión precompilada para Windows](https://fran.cr/jenkins/job/firmador/job/master/lastSuccessfulBuild/artifact/*zip*/firmador.zip).


Estado del desarrollo
---------------------

El firmador actualmente permite reemplazar la funcionalidad NexU para firmar un
documento y se ha comprobado que funciona con Firma Digital con certificados
SHA-2 de persona física en conexiones HTTP.

Queda pendiente soportar HTTPS y que el instalador o en su defecto el propio
programa sea capaz de generar una CA raíz para localhost y agregarla en los
llaveros con confianza a nivel usuario o de sistema para su uso en sitios web
con este protocolo seguro.


### Características implementadas

* Acceso al dispositivo de Firma Digital
* Entorno gráfico
* Selección de certificado
* Solicitud de PIN
* Proceso de firma
* Manejo de JSON en el servicio web
* Obtención y envío de la cadena de certificados
* Recepción del resumen
* Envío del resumen firmado


### Mejoras planeadas

* HTTPS en el servicio web
* Instaladores (con generación de CA para todos los usuarios)
* Permitir firma de múltiples documentos a la vez
* Verificación del sitio que firma y visualización del resumen a firmar
* Demostración sencilla de firma del lado del servidor
* Componente JavaScript para visualizar resumen desde un sitio web remoto
* Posibilidad de firmar con certificado de persona jurídica y otras jerarquías
* Capacidad para generar CA sin instalador (para el usuario local)
* Levantar servicio por activación socket de systemd en GNU/Linux
* Repositorios yum y apt para distribuciones GNU/Linux
* App Bundle firmado para macOS
* Instalador y/o ejecutable firmados para Windows
* Construcción automatizada continua de binarios para GNU/Linux y macOS


Motivación
----------

Este proyecto pretende ofrecer un firmador de escritorio ligero como
alternativa a firmadores basados en Java, como los del BCCR y SICOP, que
consumen una cantidad significativa de recursos en las máquinas de los
escritorios de los usuarios, cuando lo único que se requiere realmente es
acceso al dispositivo para firmar, ya que el resto de las operaciones se pueden
realizar perfectamente del lado del servidor. El uso de C++ permite crear
un firmador multiplataforma nativo, sin requerir de máquina virtual java
específica o una dependencia de librerias de gran tamaño. El espacio requerido
es aproximadamente una décima parte, siendo el consumo de RAM también varias
veces menor, así como el tiempo de carga de la aplicación.

Si existiera la posibilidad de disponer de un firmador genérico que todas las
instituciones pudieran adoptar permitiría no tener que instalar múltiples
firmadores de gran tamaño para cada institución, facilitando la instalación y
mantenimiento de los equipos de escritorio, así como de sus requerimientos. La
licencia de este proyecto y su código abierto permiten su adopción por parte
de las instituciones, así como su posible colaboración para proponer mejoras
o mejorar el código para el interés común.


Licencia
--------

Copyright © 2018 Francisco de la Peña Fernández.

Este programa es software libre, distribuido bajo la licencia GPL versión 3 o
en sus versiones posteriores.

El texto de la licencia está disponible en el fichero COPYING.
