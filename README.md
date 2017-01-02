Firmador
========

Firmador es una herramienta que permite comunicar navegadores web con
tarjetas de firma digital. Los sitios web pueden solicitar al firmador
un certificado de la tarjeta y solicitar firmar un resumen criptográfico
con la clave privada de la tarjeta asociado al certificado.

El proyecto está diseñado para uso con el sistema de Firma Digital de
Costa Rica, aunque podría resultar útil para otros países.


Funcionamiento
--------------

El desarrollo se inspira en un servicio de escritorio que recibe de un sitio
web una petición a una dirección local y puerto conocidos una serie de
peticiones a rutas específicas, tratándose de un servicio RESTful en JSON.
La comunicación entre el sitio web y el cliente se realiza por HTTPS, por lo
que el servicio local debe tener utilizar un certificado. El instalador del
servicio de escritorio deberá generar una CA en la propia máquina, agregar
confianza y generar un certificado de servidor para este servicio.

El servicio de escritorio solamente se encargará de firmar los resúmenes
criptográficos, el sitio web será el encargado del resto de la operación,
por ejemplo, agregar la firma a un documento.

Por seguridad, el sitio web antes de solicitar firmar debería mostrar al
usuario que se va a proceder a firmar un resumen criptográfico e indicar el
resumen. Una vez se abra la ventana del firmador de escritorio, aparecerá el
nombre del sitio web, se verificará que el sitio que pide firmar sea seguro
y mostrará el resumen al usuario, para que solamente acepte firmar si se le
ha solicitado y si el resumen coincide con el que se le mostró en el sitio
web.

La API REST de comunicación con el servidor sería compatible con la utilizada
por el proyecto [DSS](https://joinup.ec.europa.eu/asset/sd-dss/description),
para poder llegar a ser un reemplazo compatible con la herramienta NexU pero
sin requerir Java en el escritorio, permitiendo que la herramienta sea más
ligera de dependencias, menor tamaño y menor consumo de memoria RAM.

El servicio de escritorio será compatible con GNU/Linux, macOS y Windows.


Tecnologías usadas
------------------

* [GnuTLS](https://gnutls.org/) compilado con p11-kit, que incluye todos los
  servicios criptográficos necesarios para comunicarse con la tarjeta.

* [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/) para el
  componente RESTful de escritorio.

* [wxWidgets](https://wxwidgets.org/) como interfaz gráfica multiplataforma
  nativa.


Instalación
-----------

### Requerimientos

* Compilador de lenguaje C++.
* Cabeceras de desarrollo de GnuTLS, libmicrohttpd y wxWidgets.
* Autoconf, Automake y pkg-config

En Fedora se pueden instalar las dependencias con:

    su -c 'dnf -y install git-core gcc-c++ automake gnutls-devel libmicrohttpd-devel wxGTK3-devel' 

En Debian se pueden instalar las dependencias con:

    su -c 'apt -y install git-core g++ automake pkg-config libgnutls28-dev libmicrohttpd-dev libwxgtk3.0-dev'


### Compilación

Si se está instalando desde el repositorio git, ejecutar la primera vez:

    git clone
    autoreconf -i

Para compilar:

    ./configure
    make


Estado del desarrollo
---------------------

Este proyecto todavía está en las primeras etapas de desarrollo.


### Partes implementadas

* Acceso a la tarjeta de firma digital.
* Solicitud de PIN.
* Selección de certificado.


### Partes pendientes de implementar

* Componente RESTful de escritorio
* Entorno gráfico
* Instaladores


Licencia
--------

Copyright © 2017 Francisco de la Peña Fernández.

Este programa es software libre, distribuido bajo la licencia GPL versión 3 o
en sus versiones posteriores.

El texto de la licencia está disponible en el fichero COPYING.

