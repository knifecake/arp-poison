# Apéndice 1: configuración de la red de pruebas estática

En esta primera versión de la red de pruebas se asignan las direcciones IP de
manera estática. De esta manera es fácil suplantar al gateway ya que su
dirección se conoce de antemano.

Las máquinas virtuales están todas --incluso el router-- basadas en *Xubuntu
18.04.2 LTS* de manera que para configurar la red se utiliza la herramienta
_netplan_[^netplan] que permite configurar las interfaces de red de manera
declarativa.

![Topología de la red con IPs estáticas](http://vghia.ii.uam.es/plantuml/svg/TP11JiCm44NNv1IZic3LAWbgeUpQiaJTi63jnfF6gkkn9XCYX3WIf-1Ys4b3MvLkBFc__-sPN--CyuhL7ZuJW6SbQgDgNAfYjsLgd5wH9OQtoWW6lYPzbNLOBl0j8Ww8M2Ftyj86NvzQMMhqFx5oLfO1BvYfFG-zLafJQzmMIcNh-FoTDGxbmoCGIqLHgPJJBHiHT23SH9SBuzVeuI4D5-qDv6cQV2L94IU0byKwb70JJV3-yrs8sQlWYp514F9FaCtpIJPxd4pda-dzmHegAvJhAhXcpJlM7VhGC8HT1VaOibZAUIexfePnO3m-3GvVdyX_svYWS-WawG6CVBEnfW3ZHz4-u5y0){ width=50% }

Se utilizan las siguientes directivas para configurar las distintas máquinas:

```yaml
# configuración del router
!include(../static-net/router-netplan.yml)

# configuración del atacante
!include(../static-net/attacker-netplan.yml)

# configuración de la víctima
!include(../static-net/victim-netplan.yml)
```

[^netplan]: Netplan, The network configuration abstraction renderer. Canonical Ltd. https://netplan.io
