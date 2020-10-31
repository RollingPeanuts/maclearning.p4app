from mininet.topo import Topo

class SingleSwitchTopo(Topo):
	def __init__(self, n, **opts):
        	Topo.__init__(self, **opts)

        	switch = self.addSwitch('s1')

        	for i in xrange(1, n+1):
            		host = self.addHost('h%d' % i,
                        	ip = "10.0.0.%d" % i,
                                mac = '00:00:00:00:00:%02x' % i)
            		self.addLink(host, switch, port2=i)

class TwoSwitchTopo(Topo):
	def __init__(self, n, **opts):
        	Topo.__init__(self, **opts)

        	switch1 = self.addSwitch('s1')
		switch2 = self.addSwitch('s2')
		
		host11 = self.addHost('h1', ip = '10.0.0.1', mac = '00:00:00:00:00:01') # S1 cpu
		self.addLink(host11, switch1, port2=1)

		host12 = self.addHost('h2', ip = '10.0.0.2', mac = '00:00:00:00:00:02')
		self.addLink(host12, switch1, port2=2)

		host21 = self.addHost('h3', ip = '10.0.1.1', mac = '00:00:00:00:00:03') # S2 cpu
		self.addLink(host21, switch2, port2=1)
	
		host22 = self.addHost('h4', ip = '10.0.1.2', mac = '00:00:00:00:00:04')
		self.addLink(host22, switch2, port2=2)

		self.addLink(switch1, switch2, port1=3, port2=3)
	
		
		
