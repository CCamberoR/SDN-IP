#!/usr/bin/python
# -*- coding: utf-8 -*-

from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.node import RemoteController

CONTROLLER_IP = '127.0.0.1' 
CONTROLLER_PORT = 6633  

def myTopology():
    
    net = Mininet(topo=None, build=False, controller=None)
    
    h1 = net.addHost('h1', ip='10.0.1.100/24', defaultRoute="via 10.0.1.1", mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.2.100/24', defaultRoute="via 10.0.2.1", mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.3.100/24', defaultRoute="via 10.0.3.1", mac='00:00:00:00:00:03')

    # Agregar un controlador remoto a la red Mininet
    net.addController(name='c1', controller=RemoteController, ip=CONTROLLER_IP, port=CONTROLLER_PORT)

    s1 = net.addSwitch(name='s1')
	
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.addLink(h3, s1)
	
    net.start()
    
    CLI(net)

    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    myTopology()

