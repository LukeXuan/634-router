from mininet.topo import Topo

class SingleSwitchTopo(Topo):
    def __init__(self, n, **opts):
        Topo.__init__(self, **opts)

        sw1, sw2 = self.addSwitch('s1'), self.addSwitch('s2')

        for i in xrange(1, n+1):
            host = self.addHost('h1_%d' % i,
                                ip = "10.0.%d.1" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            self.addLink(host, sw1, port2=i)

            host = self.addHost('h2_%d' % i,
                                ip = "10.0.%d.1" % (i + 100),
                                mac = '00:00:00:00:00:%02x' % (i + 100))
            self.addLink(host, sw2, port2=i)

        self.addLink(sw1, sw2, port1=n+1, port2=n+1)
