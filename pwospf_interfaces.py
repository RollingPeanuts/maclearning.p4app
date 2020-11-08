#from globalNames import Pwospf_intf, Pwospf_neighbor, MAX_INTF
from scapy.all import Packet, Ether, IP, ARP
from cpu_metadata import CPUMetadata
from periodic_send import PeriodicSenderThread
from pwospf import Pwospf, Hello
from collections import namedtuple

Pwospf_intf = namedtuple('Pwospf_intf', ['ip', 'mask', 'helloint', 'neighbors'])
Pwospf_neighbor = namedtuple('Pwospf_neighbor', ['id', 'ip'])

MAX_INTF = 8

class PwospfIntf():
	def __init__(self, sw, routerId, areaId):
	        # PWOSPF Interface Setup 
		self.sw = sw
		self.routerId = routerId
		self.areaId = areaId
                self.pwospf_intfs = []
                #TODO: Need to exclude adding interface 1, should never send back to CPU
                for i in range(1, MAX_INTF + 1): # Take the first 8 ip values
                        ip = '10.0.' + str(routerId) + '.' + str(i)
                        mask = '255.255.255.0'
                        helloint = 30
                        neighborList = {}
                        self.pwospf_intfs.append(Pwospf_intf(ip, mask, helloint, neighborList))

                        # Match pwospf interface number with egress port number
                        self.sw.insertTableEntry(table_name='MyIngress.local_fwd',
                                match_fields={'hdr.ipv4.srcAddr': [ip]},
                                action_name='MyIngress.set_egr',
                                action_params={'port': i})

                # Initialize periodic pwospf hello pkt senders 
                self._helloSenderList = []; 
                helloPktList = [] 
                #for i in range(2, 3): # To port 3 
                for i in range(0, MAX_INTF): 
                        if(i == 0): # First port is always connected exclusively to CPU, hello message should not be sent to CPU 
                                helloPktList.append(None) 
                        else: 
                                #TODO: Checksum aint right 
                                helloPktList.append(Ether()/CPUMetadata(fromCpu=1, origEtherType=0x800)/IP(src=self.pwospf_intfs[i].ip, dst='224.0.0.5', proto=89)/Pwospf(type=1, length=32, routerId=self.routerId, areaId=self.areaId, checksum=0)/Hello(networkMask=self.pwospf_intfs[i].mask, helloInt=self.pwospf_intfs[i].helloint)) 
                #helloPktList[0].show2() 
                for i in range(0, MAX_INTF): # Set up hello senders for each port except 1 
                        if(i == 0): 
                                self._helloSenderList.append(None) 
                        else: 
                                self._helloSenderList.append(PeriodicSenderThread(sw=self.sw, pkt=helloPktList[i], interval=10))

	def handleHelloPkt(self, pkt):
                srcPort = pkt[CPUMetadata].srcPort 
                intf = self.pwospf_intfs[srcPort - 1] 
                if(pkt[Hello].networkMask != intf.mask): return 
                if(pkt[Hello].helloInt != intf.helloint): return 

                pktRouterId = pkt[Pwospf].routerId;
                srcIP = pkt[IP].src;

                if srcIP not in intf.neighbors:
                        intf.neighbors[srcIP] = pktRouterId
                        print(srcIP, pktRouterId)
                else:
                        # Update Last Hello Packet Received Timer 
                        pass
	
	def startHelloSenders(self):
		for i in range(0, MAX_INTF): # Start up hello senders for each port except 1 
                	if(i == 0): 
                        	continue 
                        else: 
                                self._helloSenderList[i].start()


