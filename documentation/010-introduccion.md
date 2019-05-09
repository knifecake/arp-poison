# Introducción

El envenenamiento ARP consiste aprovechar las vulnerabilidades del protocolo
encargado de traducir direcciónes de nivel de red (o direcciones IP) a
direcciones de nivel físico (o direcciones MAC). De esta manera un equipo
malicioso puede hacer creer a otros equipos de la red local que él es en
realidad otro host. Generalmente este tipo de ataques van enfocados a envenenar
las tablas ARP de las víctimas de manera que la entrada correspondiente a la
dirección IP del *gateway* (o puerta de enlace) apunte a la dirección MAC del
atacante. El objetivo final suele ser la suplantación de algún host,
generalmente fuera de la red local para interceptar información con fines
maliciosos aunque es posible utilizar esta técnica con fines legítimos.

![MitM attack using ARP poisoning/spoofing.[@arp-mitm-img]](https://upload.wikimedia.org/wikipedia/commons/3/33/ARP_Spoofing.svg){ width=50% }

En este documento se tratan el protocolo ARP y sus vulnerabilidades, se
muestran los resultados de un experimento en el que se aprovechan dichas
vulnerabilidades y finalmente se describen mecanismos para prevenirlo. El
grueso del contenido está dedicado a explicar el proceso de explotación de las
vulnerabilidades descritas en la primera sección en un entorno controlado pero
con versiones actuales de sistemas operativos haciendo patente el posible
impacto de un ataque de este tipo.
