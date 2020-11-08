from p4app import P4Mininet
from my_topo import SingleSwitchTopo, TwoSwitchTopo
from controller import MacLearningController

import time

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

#topo = SingleSwitchTopo(N)
topo = TwoSwitchTopo(N)
net = P4Mininet(program='l2switch.p4', topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
bcast_mgid = 1
sw1 = net.get('s1')
sw2 = net.get('s2')
sw1.addMulticastGroup(mgid=bcast_mgid, ports=range(2, N+1))

# Send MAC bcast packets to the bcast multicast group
sw1.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})

sw2.insertTableEntry(table_name='MyIngress.fwd_l2',
        match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
        action_name='MyIngress.set_mgid',
        action_params={'mgid': bcast_mgid})

#sw.insertTableEntry(table_name='MyIngress.fwd_ip',
#	match_fields={'hdr.ipv4.dstAddr': ["224.0.0.5"]},
#	action_name='MyIngress.set_mgid',
#	action_params={'mgid': bcast_mgid})


# Start the MAC learning controller
areaId = 0
routerId = 0
cpu1 = MacLearningController(sw1, areaId, routerId)
cpu1.start()

routerId2 = 1
cpu2 = MacLearningController(sw2, areaId, routerId2)
cpu2.start()

h2, h4 = net.get('h2'), net.get('h4')
#print sw1.deleteTableEntry

#print topo.links();
#print h2.cmd('arping -c1 10.0.0.3')

#print h3.cmd('ping -c1 10.0.0.2')
#p = PeriodicSenderThread(sw, None, 3)
#p.start()
time.sleep(10)
#p.join()

# These table entries were added by the CPU:
sw1.printTableEntries()
sw2.printTableEntries()
