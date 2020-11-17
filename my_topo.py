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
		
		host13 = self.addHost('h5', ip = '10.0.0.3', mac = '00:00:00:00:00:05')
		self.addLink(host13, switch1, port2 = 4)

def hostIP(i, n):
    return "10.0.%d.%d" % (i, n)

def hostMAC(i, n):
    return '00:00:00:00:%02x:%02x' % (i, n)

class RingTopo(Topo):
#TODO: Finish this topo and set up in main
	def __init__(self, n, **opts):
        	Topo.__init__(self, **opts)

		switches = []

		for i in xrange(0, n):
			host1 = self.addHost('h%d1' % i,
					ip = hostIP(i, 1),
					mac = hostMAC(i, 1)) 
			host4 = self.addHost('h%d4' % i,
					ip = hostIP(i, 4),
					mac = hostMAC(i, 4)) 
			switch = self.addSwitch('s%d' % i)
			self.addLink(host1, switch, port2=1)
			self.addLink(host4, switch, port2=4)

			if(i == 0):
				host5 = self.addHost('h%d5' % i,
						ip = hostIP(i, 5),
						mac = hostMAC(i, 5)) 
				self.addLink(host5, switch, port2=5)
			switches.append(switch)

		# Port 2 connects to the next switch in the ring, and port 3 to the previous
		for i in xrange(n):
			self.addLink(switches[i], switches[(i+1)%n], port1=2, port2=3)	
		
