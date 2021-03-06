from p4app import P4Mininet
from my_topo import SingleSwitchTopo, TwoSwitchTopo, RingTopo
from controller import MacLearningController

import time 
from packetTest import testPacket

#testpkt = testPacket()
#while(True):
#	continue

# Add three hosts. Port 1 (h1) is reserved for the CPU.
#N = 8
N = 5

#topo = SingleSwitchTopo(N) 
topo = RingTopo(N) 
net = P4Mininet(program='l2switch.p4', topo=topo, auto_arp=False)
net.start()


# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
switches = []
hosts = []
for i in range(0, N):
	switches.append(net.get('s%d' % i))
	hosts.append(net.get('h%d4' % i))
host05 = net.get('h05')
#print switches
#for host in hosts:
	#print(host)
	#print(host.MAC())
	#print(host.IP())
#print(host05)
#print(host05.MAC())
#print(host05.IP())

# Send MAC bcast packets to the bcast multicast group
for sw in switches:
	sw.addMulticastGroup(mgid=bcast_mgid, ports = [4,5])
	sw.insertTableEntry(table_name='MyIngress.fwd_l2',
		match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
		action_name='MyIngress.set_mgid',
		action_params={'mgid': bcast_mgid})

#sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
#        match_fields={'hdr.ethernet.dstAddr': ["00:00:00:00:00:00"]},
#        action_name='MyIngress.set_mgid',
#        action_params={'mgid': 100})

#sw1.removeTableEntry(0)
#sw1.printTableEntries()

#print sw1.ReadTableEntries
#while True:
#	continue;
#sw.insertTableEntry(table_name='MyIngress.fwd_ip',
#	match_fields={'hdr.ipv4.dstAddr': ["224.0.0.5"]},
#	action_name='MyIngress.set_mgid',
#	action_params={'mgid': bcast_mgid})

# Start the MAC learning controller
areaId = 0
cpus = []
for routerId in range(0, N):
	cpu = MacLearningController(switches[routerId], areaId, routerId)
	cpu.start()
	cpus.append(cpu)

#print sw1.deleteTableEntry

#print topo.links();
#print h2.cmd('arping -c1 10.0.0.3')
time.sleep(80)
#print h2.cmd('arping -c1 10.0.7.0')
#print h2.cmd('ping -c1 10.0.7.0')
#print h4.cmd('arping -c1 10.0.1.2') #TODO: can uncomment this later
#print h2.cmd('ping -c1 10.0.1.2')
#print h2.cmd('ping -c1 10.0.0.7')
print host05.cmd('ping -c1 10.0.0.4')
print hosts[0].cmd('ping -c1 10.0.3.4')
print hosts[3].cmd('ping -c1 10.0.4.4')
print hosts[1].cmd('ping -c1 10.0.2.4')
print hosts[2].cmd('ping -c1 10.0.1.4')
print hosts[4].cmd('ping -c1 10.0.0.5')
#print h3.cmd('ping -c1 10.0.0.2')
#p = PeriodicSenderThread(sw, None, 3)
#p.start()
#time.sleep(80)
#time.sleep(180)
#p.join()

# These table entries were added by the CPU:
for sw in switches:
	sw.printTableEntries()
#sw1.printTableEntries()
#sw2.printTableEntries()
