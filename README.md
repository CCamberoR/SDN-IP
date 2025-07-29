# SDN-IP

Un proyecto de Software-Defined Networking (SDN) que implementa un forwarder/switch de capa 3 utilizando el controlador POX y Mininet para la simulación de red.

## Descripción

Este proyecto implementa un router SDN que funciona como un forwarder de capa 3 con las siguientes características:

- **Switch de Capa 3**: Actúa como un forwarder/switch de capa 3, no como un router tradicional
- **Sin decrementación de TTL**: No decrementa el TTL de los paquetes
- **Recompute de checksum**: Recomputa el checksum en cada salto (el traceroute no funciona como esperado)
- **Enrutamiento estático**: Utiliza rutas completamente estáticas (sin BGP, sin OSPF)
- **Subredes configuradas**: Cada nodo de la red tiene una subred configurada

### Comportamiento del Switch

El comportamiento del switch depende del destino del paquete:

- **Hacia un host local**: El nodo actúa como un switch y redirecciona el paquete sin cambios hacia el puerto conocido o realiza broadcast
- **Hacia una dirección IP conocida**: Modifica la dirección MAC de destino de capa 2 y redirecciona el paquete hacia el puerto correcto

## Arquitectura

```
┌───────────────┐  ┌───────────────┐  ┌───────────────┐
│      H1       │  │      H2       │  │      H3       │
│ 10.0.1.100/24 │  │ 10.0.2.100/24 │  │ 10.0.3.100/24 │
└───────┬───────┘  └───────┬───────┘  └───────┬───────┘
        │                  │                  │
        └──────────────────┼──────────────────┘
                           │
                   ┌───────┴───────┐
                   │      S1       │
                   │   (Switch)    │
                   └───────┬───────┘
                           │
                   ┌───────┴───────┐
                   │ POX Controller│
                   │   (SDN-IP)    │
                   └───────────────┘
```

## Prerrequisitos

### Software requerido

- **Python 3.6+**
- **POX Controller**: Controlador OpenFlow para SDN
- **Mininet**: Emulador de red para prototipado de redes SDN
- **Open vSwitch**: Switch virtual compatible con OpenFlow

### Instalación de dependencias

#### Ubuntu/Debian
```bash
# Actualizar el sistema
sudo apt update

# Instalar dependencias básicas
sudo apt install python3 python3-pip git

# Instalar Mininet
sudo apt install mininet

# Instalar Open vSwitch
sudo apt install openvswitch-switch

# Instalar POX (ya incluido en este proyecto)
# El controlador POX está incluido en la carpeta controller/
```

#### Desde código fuente (alternativo)
```bash
# Clonar e instalar Mininet
git clone https://github.com/mininet/mininet
cd mininet
sudo util/install.sh -a

# El proyecto ya incluye POX en la carpeta controller/
```


## Instalación y Configuración

1. **Clonar el repositorio**
```bash
git clone https://github.com/CCamberoR/SDN-IP.git
cd SDN-IP
```

2. **Instalar dependencias de Python**
```bash
pip3 install -r requirements.txt
```

3. **Verificar instalación de Mininet**
```bash
sudo mn --test pingall
```

## Uso del Proyecto

### Iniciar el sistema

Necesitarás **dos terminales** para ejecutar el proyecto:

#### Terminal 1: Iniciar el controlador POX
```bash
cd controller/
./pox.py samples.pretty_log misc.sdn_ip
```

#### Terminal 2: Iniciar la topología Mininet
```bash
sudo python3 topology.py
```

### Comandos útiles en Mininet

Una vez que la topología esté ejecutándose, puedes usar los siguientes comandos en la CLI de Mininet:

```bash
# Verificar conectividad entre todos los hosts
mininet> pingall

# Ping entre hosts específicos
mininet> h1 ping h2

# Ver la tabla de flujos del switch
mininet> sh ovs-ofctl dump-flows s1

# Ejecutar comandos en hosts específicos
mininet> h1 ifconfig
mininet> h2 arp -a

# Salir de Mininet
mininet> exit
```

## Estructura del Proyecto

```
SDN-IP-main/
├── README.md                    # Este archivo
├── requirements.txt             # Dependencias de Python
├── topology.py                  # Definición de la topología de red
└── controller/                  # Controlador POX
    ├── pox.py                   # Script principal de POX
    └── pox/
        ├── misc/
        │   └── sdn_ip.py        # Implementación del switch SDN-IP
        ├── openflow/            # Módulos OpenFlow
        ├── forwarding/          # Algoritmos de forwarding
        └── lib/                 # Librerías auxiliares
```

## Componentes Técnicos

### Estructuras de Datos Principales

El controlador SDN-IP utiliza las siguientes estructuras de datos:

- **`cache_arp`**: Tabla que contiene la asociación entre direcciones IP y direcciones MAC
- **`routing_table`**: Estructura para almacenar rutas estáticas
- **`port_to_ip`**: Mapeo entre puertos de salida y direcciones IP de destino
- **`message_queue`**: Cola de mensajes para almacenar paquetes temporalmente hasta que puedan ser procesados

### Algoritmo Principal: `_handle_PacketIn`

El funcionamiento principal de la aplicación se encuentra en el método `_handle_PacketIn`, que contiene la lógica de forwarding de paquetes cuando se recibe un evento de llegada de paquetes:

#### Manejo de Paquetes ARP
```python
if packet.type == packet.ARP_TYPE:
    if packet.payload.opcode == arp.REQUEST:
        # Se envía un ARP reply
    elif packet.payload.opcode == arp.REPLY:
        # Se guarda la MAC en la caché ARP
        self.cache_arp[packet.payload.protosrc] = packet.src 
        # Se guarda la IP y el puerto de salida en la tabla de enrutamiento
        self.routing_table[packet.payload.protosrc] = packet_in.in_port 
        # Al recibir una MAC nueva, se procesan los paquetes en cola para ese host
```

#### Manejo de Paquetes IP
```python
elif packet.type == packet.IP_TYPE:
    if isinstance(ip_packet, ipv4):  # Verificar que sea IPv4
        if ip_packet.dstip in self.port_to_ip.values() or isIn:  # IP conocida
            if ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
                icmp_packet = ip_packet.payload
                if ip_packet.dstip in self.port_to_ip.values():
                    # Ping al switch
                elif ip_packet.dstip not in self.cache_arp:
                    # MAC desconocida - encolar paquete y enviar ARP request
                    self.message_queue.append(event)
                else:
                    # MAC conocida - reenviar paquete
```

## Características de la Implementación

### Protocolo ARP
- Manejo completo de solicitudes y respuestas ARP
- Caché ARP para almacenar asociaciones IP-MAC
- Generación automática de respuestas ARP para IPs locales

### Protocolo ICMP
- Soporte para ping entre hosts
- Generación de mensajes ICMP Host Unreachable
- Forwarding de paquetes ICMP entre subredes

### Forwarding de Paquetes
- Reescritura de direcciones MAC para routing inter-subnet
- Cola de mensajes para paquetes pendientes de resolución ARP
- Forwarding basado en tabla de rutas estáticas

## Resolución de Problemas

### Problemas Comunes

1. **Error de permisos en Mininet**
   ```bash
   sudo python3 topology.py
   ```

2. **POX no encuentra módulos**
   ```bash
   cd controller/
   export PYTHONPATH=$PWD:$PYTHONPATH
   ./pox.py samples.pretty_log misc.sdn_ip
   ```

3. **Switch no se conecta al controlador**
   - Verificar que el controlador esté ejecutándose en el puerto 6633
   - Comprobar la configuración de IP del controlador en `topology.py`

4. **Hosts no pueden hacer ping**
   - Verificar las rutas estáticas en el código del controlador
   - Comprobar la tabla ARP: `mininet> h1 arp -a`
   - Ver logs del controlador para debugging

### Logs y Debugging

Para ver logs detallados del controlador:
```bash
./pox.py log.level --DEBUG samples.pretty_log misc.sdn_ip
```

Para ver la tabla de flujos del switch:
```bash
sudo ovs-ofctl dump-flows s1
```

## Contribuir

1. Fork el proyecto
2. Crear una rama para tu feature (`git checkout -b feature/AmazingFeature`)
3. Commit tus cambios (`git commit -m 'Add some AmazingFeature'`)
4. Push a la rama (`git push origin feature/AmazingFeature`)
5. Abrir un Pull Request

## Licencia

Este proyecto está bajo la Licencia Apache 2.0. Ver el archivo `LICENSE` para más detalles.

## Referencias

- [POX Documentation](https://github.com/noxrepo/pox)
- [Mininet Documentation](http://mininet.org/)
- [OpenFlow Specification](https://www.opennetworking.org/software-defined-standards/specifications/)
- [Software-Defined Networking (SDN)](https://en.wikipedia.org/wiki/Software-defined_networking)

