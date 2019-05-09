# ARP Poisoning: descripción, implementación y mitigación de un ataque de suplantación mediante envenenamiento ARP

## Temática

*ARP poisoning* es una técnica que permite manipular las tablas ARP presentes
en hosts dentro de una red de área local. Interceptando el tráfico ARP que se
produzca en la red es posible convencer a un host víctima de que la dirección
MAC del *gateway* de la LAN es en realidad la del atacante. Esta información
permanece almacenada en los hosts infectados durante algún tiempo lo que
permite manipular el tráfico entre estos y otros hosts fuera de la LAN. En
particular, es posible obtener datos sobre los hosts con los que las víctimas
se comunican y, en caso de que se utilicen protocolos inseguros, manipular el
tráfico obteniendo así más que metadatos.

## Objetivos

En este trabajo proponemos la implementación de este ataque en un entorno
virtual controlado. El objetivo es que un par de máquinas virtuales conectadas
a una misma red virutalizada jueguen los papeles de atacante y víctima. El
atacante escuchará en espera de tráfico ARP y al detectarlo intentará suplantar
la identidad del gateway de la LAN. En caso de conseguirlo, la víctima, una
máquina virtual sin modificaciones especiales, pasará a estar tras un *proxy*
(el atacante) que filtrará todo el tráfico dirigido a hosts fuera de la LAN que
genere la víctima. Para demostrarlo, el atacante manipulará todo fichero HTML
transmitido a través de HTTP (no HTTPS) y reemplazará las imágenes presentes en
las páginas por otras elegidas aleatoriamente.

Finalmente, se discutirán posibles estrategias para mitigar dichos ataques, como
la adición una entrada estática para el gateway en la tabla ARP de los hosts o
el uso de soluciones más sofisticadas de detección y mitigación de este ataque.

## Desarrollo

El proyecto consiste principalmente de tres partes:

1. **Investigación sobre el funcionamiento de un ataque de suplantación ARP.**
   El objetivo principal de esta fase es familiarizarse con el ataque desde un
   punto de vista teórico y práctico. En concreto se plantea el análisis de
   herramientas como Ethercap, presente en el sistema operativo Kali Linux.
   Esta herramienta es capaz de ejecutar un ataque en un entorno controlado.
   Mediante la inspección del tráfico con Wireshark es posible entender cómo se
   ha de implementar el ataque. Además, se plantea el estudio de herramientas
   de mitigación como Antidote de cara a entender qué dificultades pueden
   aparecer a la hora de implementar el ataque.

2. **Implementación del ataque de suplantación ARP.** Desarrollo de un programa
   capaz de detectar tráfico ARP, en concreto paquetes de tipo `ARP_REQUEST` y
   contestar con paquetes maliciosos diseñados para suplantar la MAC del
   gateway en las tablas ARP de la víctima. Este software se desarrollará para
   Linux y se probará en un entorno controlado mediante virtualización de la
   red y los sistemas operativos.

3. **Implementación del proxy para el ataque MITM.** Desarrollo de un programa
   que filtre el tráfico y retenga las respuestas al protocolo HTTP que vayan
   destinadas a la víctima. En caso de tratarse de archivos HTML los modifica
   para sustituir las imágenes por otras. El objetivo de esta parte es
   demostrar de manera clara la viabilidad de este tipo de ataque,
   especialmente en caso de no utilizar protocolos seguros como HTTPS.
