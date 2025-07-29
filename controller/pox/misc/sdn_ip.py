# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
from pox.lib.packet import icmp
from pox.lib.packet.icmp import TYPE_DEST_UNREACH, CODE_UNREACH_HOST, TYPE_ECHO_REPLY
from pox.lib.packet import arp
from pox.lib.packet.ipv4 import ipv4
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.packet.ethernet import ethernet
import ipaddress


log = core.getLogger()



class SDN_IP (object):
  """
  A Tutorial object is created for each switch that connects.
  A Connection object for that switch is passed to the __init__ function.
  """
  def __init__ (self, connection):
    # Crea la conexión
    self.connection = connection

    # Crea un listener para la conexión
    connection.addListeners(self)

    #tabla enrutamiento ip->puerto vacio
    self.routing_table = {}

    #map<port> -> ip del switch
    self.port_to_ip = {
      1 : IPAddr('10.0.1.1'),
      2 : IPAddr('10.0.2.1'),
      3 : IPAddr('10.0.3.1')
    }

    #map<port> -> ip del switch
    self.port_to_mac = {
      1 : EthAddr('11:11:11:11:11:11'),
      2 : EthAddr('22:22:22:22:22:22'),
      3 : EthAddr('33:33:33:33:33:33')
    }

    #cache para arp, almacena MAC's y la IP de los hosts
    self.cache_arp = {
      IPAddr('10.0.1.1') : EthAddr('11:11:11:11:11:11'),
      IPAddr('10.0.2.1') : EthAddr('22:22:22:22:22:22'),
      IPAddr('10.0.3.1') : EthAddr('33:33:33:33:33:33')
    }

    # Cola de mensajes para almacenar temporalmente los mensajes arp request
    self.message_queue = []

  # Construir paquete ARP
  def build_arp (self, hwsrc, hwdst, opcode, protosrc, protodst):
    log.info("Creating arp packet...")
    arp_packet = arp()
    arp_packet.hwsrc = hwsrc
    arp_packet.hwdst = hwdst
    arp_packet.opcode = opcode
    arp_packet.protosrc = protosrc
    arp_packet.protodst = protodst
    return arp_packet
  
  # Construir paquete ethernet
  def build_ethernet(self, src, dst, type, payload):
    log.info("Creating ethernet packet...")
    ether_packet = ethernet()
    ether_packet.src = src
    ether_packet.dst = dst
    ether_packet.type = type
    ether_packet.payload = payload
    return ether_packet

  #Construir paquete ip
  def build_ip(self, srcip, dstip, protocol, payload ):
    log.info("Creating ip packet...")
    ip_packet = ipv4()
    ip_packet.srcip = srcip
    ip_packet.dstip = dstip
    ip_packet.protocol = protocol
    ip_packet.payload = payload
    return ip_packet

  #Construir paquete icmp
  def build_icmp(self, type, code, payload):
    log.info("Creating icmp packet...")
    icmp_packet = icmp()
    icmp_packet.type = type
    icmp_packet.code = code
    icmp_packet.payload = payload
    return icmp_packet


  #Gestiona los paquetes del switch
  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # Datos parseados del paquete.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # ofp_packet del mensaje.
    
    # Gestión de paquetes ARP
    if packet.type == packet.ARP_TYPE:
      # Si se solicita una MAC de las interfaces del switch se envía un ARP Reply  
      if packet.payload.opcode == arp.REQUEST:
        log.info("Received arp request")
        # Construir reply con mac origen (eth s1), mac dst (origen del paquete), opcode, ip src 
        arp_reply = self.build_arp(self.port_to_mac[packet_in.in_port], packet.src, arp.REPLY, self.port_to_ip[packet_in.in_port], packet.payload.protosrc)
        # Construir paquete IP
        ether_reply = self.build_ethernet(self.port_to_ip[packet_in.in_port].toRaw(), packet.src, ethernet.ARP_TYPE, arp_reply.pack())
        # Crear salida de paquete IP
        msg = of.ofp_packet_out(data = ether_reply) 
        # Enviar paquete IP por el puerto correspondiente
        msg.actions.append(of.ofp_action_output(port = packet_in.in_port))
        # Guardar en la tabla arp la mac del host origen. Si ya existe, se sustituye.
        self.cache_arp[packet.payload.protosrc] = packet.src
        # Guardar en la tabla de ruta el puerto asociado a la IP del host origen.
        self.routing_table[packet.payload.protosrc] = packet_in.in_port 
        # Envío del paquete
        event.connection.send(msg) 
      
      # Si es un ARP Reply, hemos recibido una MAC nueva
      elif packet.payload.opcode == arp.REPLY: 
        log.info("Received arp reply")
        # Se guarda la mac a la caché ARP
        self.cache_arp[packet.payload.protosrc] = packet.src 
        # Se guarda la ip y el puerto de salida en la tabla de enrutamiento
        self.routing_table[packet.payload.protosrc] = packet_in.in_port 
        
        # Al recibir una mac nueva, se tratan los paquetes en espera del buffer para ese host
        for packet_queued in self.message_queue: 
          log.info("Se tratan los paquetes del buffer para la MAC guardada")
          # Se tratan los paquetes en espera con destino la mac recién añadida
          if packet_queued.parsed.payload.dstip == packet.payload.protosrc:
            # Se cambia la mac origen por la mac de la interfaz del switch de salida del paquete
            packet_queued.parsed.src = self.port_to_mac[self.routing_table[packet_queued.parsed.payload.dstip]] 
            # Se cambia la mac destino a la recién añadida
            packet_queued.parsed.dst = self.cache_arp[packet_queued.parsed.payload.dstip]
            # Preparación de envío del paquete
            msg = of.ofp_packet_out(data=packet_queued.parsed.pack()) 
            # Acción: enviar paquete por puerto correspondiente según la tabla de enrutamiento
            msg.actions.append(of.ofp_action_output(port=self.routing_table[packet_queued.parsed.payload.dstip])) 
            # Envío del paquete
            event.connection.send(msg) 
            
            # Instalar una regla de flujo en la que el match es la ip destino y la MAC de origen
            flow_mod = of.ofp_flow_mod()
            flow_mod.match.dl_type = ethernet.IP_TYPE
            # Match: IP destino = IP origen
            flow_mod.match.nw_dst = packet.payload.protosrc
            # Acción: cambiar mac origen por mac de interfaz de s1 de salida
            flow_mod.actions.append(of.ofp_action_dl_addr.set_src(self.port_to_mac[self.routing_table[packet_queued.parsed.payload.dstip]]))
            # Cambiar mac destino por mac del host
            flow_mod.actions.append(of.ofp_action_dl_addr.set_dst(self.cache_arp[packet_queued.parsed.payload.dstip]))
            # Enviar paquete por puerto correspondiente
            flow_mod.actions.append(of.ofp_action_output(port=self.routing_table[packet_queued.parsed.payload.dstip]))
            event.connection.send(flow_mod)

        # Eliminar los paquetes tratados del buffer    
        self.message_queue = [p for p in self.message_queue if p.parsed.payload.dstip != packet.payload.protosrc] 

      # Si no es un ARP Request ni un ARP Reply, no se hace nada.  
      else:
        print ("Some other ARP opcode, probably do something smart here")
    
    # Si no es de tipo ARP, puede ser un paquete IP
    elif packet.type == packet.IP_TYPE:
      log.info("Received ip packet")
      ip_packet = packet.payload
      
      # Se comprueba que es un paquete IPv4
      if isinstance(ip_packet, ipv4):
        # Se obtiene la IP destino
        dst_ip = ipaddress.IPv4Address(str(ip_packet.dstip))
        knownSubnet = False 
        # Se comprueba si es una IP conocida
        for port_ip in self.port_to_ip.values(): 
            #log.info(port_ip)
            # Obtiene la subred del puerto
            subnet = ipaddress.ip_network(str(port_ip) + '/24', strict=False) 
            #log.info(subnet)
            # Comprueba si la IP destino está en la subred
            if dst_ip in subnet:
                knownSubnet = True
                #log.info(knownSubnet)
                break
        if knownSubnet:
          # Si conocemos la ip de destino
          if ip_packet.dstip in self.port_to_ip.values():
            log.info("Ip in port_to_ip. Creating ip reply")
            ip_reply = ipv4()
            ip_reply.payload = ip_packet.payload
            # Si es un paquete ICMP
            if ip_packet.protocol == ip_packet.ICMP_PROTOCOL:
              log.info("Es tipo ICMP. Creating icmp reply")
              icmp_packet = ip_packet.payload
              icmp_reply = self.build_icmp(TYPE_ECHO_REPLY, 0, icmp_packet.payload)
              icmp_reply.srcip = ip_packet.dstip # Se asigna a la IP de origen de la reply la de destino del paquete
              icmp_reply.dstip = ip_packet.srcip # Se asigna a la IP de destino de la reply la de origen del paquete

              ip_reply.protocol = ip_reply.ICMP_PROTOCOL
              ip_reply.payload = icmp_reply
              # ip_reply = self.build_ip(ip_packet.dstip, ip_packet.srcip, ipv4.ICMP_PROTOCOL, icmp_reply)

            ip_reply.srcip = ip_packet.dstip  # Swap source and destination IP addresses
            ip_reply.dstip = ip_packet.srcip
            ether_reply = self.build_ethernet(self.port_to_mac[packet_in.in_port], self.cache_arp[ip_packet.srcip], ethernet.IP_TYPE, ip_reply)         

            msg = of.ofp_packet_out(data=ether_reply.pack())
            msg.actions.append(of.ofp_action_output(port=self.routing_table[ip_packet.srcip])) #Se envia por el puerto obtenido de la tabla de rutas
            event.connection.send(msg)

          # Si la IP destino no está en caché arp, no conocemos la IP
          else:
            # Si sabemos la MAC asociada a la IP destino se reenvía por el puerto correspondiente
            if ip_packet.dstip in self.cache_arp:  
              packet.src = self.port_to_mac[self.routing_table[packet.payload.dstip]] #Se cambia la mac de origen a la del enlace
              packet.dst = self.cache_arp[packet.payload.dstip] #Se cambia la mac de destino por la del host
              msg = of.ofp_packet_out(data=packet.pack()) 
              msg.actions.append(of.ofp_action_output(port=self.routing_table[packet.payload.dstip])) #Se envia por el puerto obtenido
              event.connection.send(msg) 

              #Instala la regla de flujo con la regla para que haga match del ip destino
              flow_mod = of.ofp_flow_mod()
              flow_mod.match.dl_type = ethernet.IP_TYPE
              flow_mod.match.nw_dst = ip_packet.dstip
              flow_mod.actions.append(of.ofp_action_dl_addr.set_src(self.port_to_mac[self.routing_table[packet.payload.dstip]]))
              flow_mod.actions.append(of.ofp_action_dl_addr.set_dst(self.cache_arp[packet.payload.dstip]))
              flow_mod.actions.append(of.ofp_action_output(port=self.routing_table[packet.payload.dstip]))
              event.connection.send(flow_mod)
            # Si no sabemos la MAC asociada a la IP destino
            else:
              log.info("No conocemos la MAC destino. Guardamos paquete en buffer")
              #Se añade el paquete al buffer para esperar a procesarlo
              self.message_queue.append(event) 
              #Se envia un ARP request a los puertos que no han recibido el mensaje
              for key in self.port_to_mac: 
                # Saltar el puerto por el que se recibe el mensaje
                if key != packet_in.in_port:
                  log.info("Enviar ARP Request por broadcast para MAC destino")
                  arp_req = self.build_arp(self.port_to_mac[key], EthAddr('00:00:00:00:00:00'), arp.REQUEST, self.port_to_ip[key],ip_packet.dstip)
                  ethernet_req = self.build_ethernet(self.port_to_mac[key], EthAddr('ff:ff:ff:ff:ff:ff'), ethernet.ARP_TYPE, arp_req.pack())
                  reqmsg = of.ofp_packet_out(data=ethernet_req) #Se envia el paquete ARP
                  reqmsg.actions.append(of.ofp_action_output(port=key)) #Se envia por los puertos del switch
                  event.connection.send(reqmsg)
                
        #Si no se envía a una dirección conocida, se envia un ICMP de host unreachable
        else: 
          log.info("Destination Host Unreacheable")
          icmp_reply = self.build_icmp(TYPE_DEST_UNREACH, CODE_UNREACH_HOST, ip_packet.payload.payload)
          ip_reply = self.build_ip(self.port_to_ip[packet_in.in_port], ip_packet.srcip, ipv4.ICMP_PROTOCOL, icmp_reply)
          ether_reply = self.build_ethernet(self.port_to_mac[packet_in.in_port], packet.src, ethernet.IP_TYPE, ip_reply)
          msg = of.ofp_packet_out(data=ether_reply.pack()) #Se envia el paquete
          msg.actions.append(of.ofp_action_output(port=packet_in.in_port)) #Se envia por el puerto por el que se ha recibido el paquete
          event.connection.send(msg)

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    SDN_IP(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)