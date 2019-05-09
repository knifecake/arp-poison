# Entorno controlado de pruebas

## Topología de red

En la red de pruebas se distinguen 3 equipos:

- El ***router*** que actúa como gateway entre la red local y el exterior. Como
  queremos aislar completamente el experimento de Internet o de la LAN real, el
  *router* actuará también como servidor DNS y redirigirá cualquier tráfico a
  sí mismo.
- El **atacante** que espera a que se produzcan peticiones ARP e intenta
  suplantar al router (intenta convertirse en el Gateway de la red).
- La **víctima** que se conecta a la red y envía peticiones ARP para averiguar
  la dirección MAC del router y sufre el ataque de suplantación.

## Implementación de la red virtual

Para la realización del experimento se han empleado tres máquinas virtuales
corriendo en VirtualBox. Las máquinas ejecutan *Xubuntu 18.04.03 LTS*. Para la
simulación de la red se ha utilizado la opción *host-only network* de
VirtualBox. Esta opción permite la comunicación entre máquinas virtuales y con
el anfitrión pero no permite que salga tráfico al exterior. Se ha elegido esta
opción frente a la opción *internal-network* porque la primera monta una
interfaz virtual en el anfitrión lo que facilita el análisis del tráfico en la
red.

Una vez creada la red virtual en VirtualBox es necesario configurar las
máquinas virtuales para que utilicen esta red añadiendo la interfaz
correspondiente. Además, es necesario configurar una IP para cada una de ellas.
Para este experimento, se ha optado por utilizar IPs estáticas. Los detalles
sobre la configuración de la red virtual y de las interfaces en las máquinas
virtuales se pueden ver en TODO.
