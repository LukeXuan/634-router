from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        sw1, sw2, sw3 = self.addSwitch('s1'), self.addSwitch('s2'), self.addSwitch('s3')

        for i in xrange(1, n+1):
            host = self.addHost('h1_%d' % i,
                                ip = "10.0.%d.1" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, sw1, port2=i)

            host = self.addHost('h2_%d' % i,
                                ip = "10.0.%d.1" % (i + 100),
                                mac = '00:00:00:00:00:%02x' % (i + 100))
            self.addLink(host, sw2, port2=i)

        self.addLink(sw1, sw3, port1=n+1, port2=2)
        self.addLink(sw2, sw3, port1=n+1, port2=3)

        host = self.addHost('h3_1', ip="10.0.201.1", mac="00:00:00:00:00:c9")
        self.addLink(host, sw3, port2=1)
