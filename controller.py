from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from collections import namedtuple
from periodic_send import PeriodicSenderThread
from pwospf import Pwospf, Hello
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
PWOSPF_TYPE_HELLO = 0x01
PWOSPF_TYPE_LSU   = 0x04
Pwospf_intf = namedtuple('Pwospf_intf', ['ip', 'mask', 'helloint', 'neighbors'])
Pwospf_neighbor = namedtuple('Pwospf_neighbor', ['id', 'ip'])

class MacLearningController(Thread):
	def __init__(self, sw, areaId, routerId, start_wait=0.3):
		super(MacLearningController, self).__init__()
		self.sw = sw
		self.start_wait = start_wait # time to wait for the controller to be listenning
		self.iface = sw.intfs[1].name
		self.port_for_mac = {}
		self.stop_event = Event()

		# PWOPSF Router Metadata
		self.routerId = routerId;
		self.areaId = areaId
		self.lsuint = 60; # 60 seconds between each link status update broadcast

		# PWOSPF Interface Setup 
		self.pwospf_intfs = []
		#TODO: Need to exclude adding interface 1, should never send back to CPU
		for i in range(1, 9): # Take the first 8 ip values
			ip = '10.0.' + str(routerId) + '.' + str(i) 
			mask = '255.255.255.0'
			helloint = 30
			#neighborList = []
			neighborList = {}
			self.pwospf_intfs.append(Pwospf_intf(ip, mask, helloint, neighborList))
			#sw.setIP(ip, prefixLen, sw.intfs[i])
			self.sw.insertTableEntry(table_name='MyIngress.local_fwd',
				match_fields={'hdr.ipv4.srcAddr': [ip]},
				action_name='MyIngress.set_egr',
				action_params={'port': i})
				

		self._helloSenderList = [];

	def addMacAddr(self, mac, port, ip):
		# Don't re-add the mac-port mapping if we already have it:
		if mac in self.port_for_mac: return

		self.sw.insertTableEntry(table_name='MyIngress.fwd_l2',
			match_fields={'hdr.ethernet.dstAddr': [mac]},
			action_name='MyIngress.set_egr',
			action_params={'port': port})
		self.port_for_mac[mac] = port

		self.sw.insertTableEntry(table_name='MyIngress.arp_cache',
			match_fields={'hdr.arp.dstIP': [ip]},
			action_name='MyIngress.return_arp',
			action_params={'cachedMac': mac})

	def handleArpReply(self, pkt):
		self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort, pkt[ARP].psrc)
		self.send(pkt)

	def handleArpRequest(self, pkt):
		self.addMacAddr(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort, pkt[ARP].psrc)
		self.send(pkt)

	def verifyPwospfChecksum(self, pkt):
		# TODO: Establish this
		return True	

	def handleHello(self, pkt, intf, routerId): 
		if(pkt[Hello].networkMask != intf.mask): return 
		if(pkt[Hello].helloInt != intf.helloint): return 
		srcIP = pkt[IP].src;
		if srcIP not in intf.neighbors:
			intf.neighbors[srcIP] = routerId;
			print(srcIP, routerId)
		else:
			# Update Last Hello Packet Received Timer 
			pass

	def handleLSU(self, pkt):
		# TODO: Finish coding this
		pass

	def handlePwospf(self, pkt):
		# TODO: Check IP header validity - make sure it is addressed to the current port
		if(pkt[Pwospf].version != 2): return
		if(pkt[Pwospf].areaId != self.areaId): return
		if(pkt[Pwospf].auType != 0): return
		if(not self.verifyPwospfChecksum(pkt)): return
	
		srcPort = pkt[CPUMetadata].srcPort
		intf = self.pwospf_intfs[srcPort - 1]
		routerId = pkt[Pwospf].routerId;
		if pkt[Pwospf].type == PWOSPF_TYPE_HELLO:
			self.handleHello(pkt, intf, routerId)
		elif pkt[Pwospf].type == PWOSPF_TYPE_LSU:
			self.handleLSU(pkt, intf)

	def handlePkt(self, pkt):
		#pkt.show2()
		assert CPUMetadata in pkt, "Should only receive packets from switch with special header"

		# Ignore packets that the CPU sends:
		if pkt[CPUMetadata].fromCpu == 1: return
		#pkt.show2()

		if ARP in pkt:
			if pkt[ARP].op == ARP_OP_REQ:
				self.handleArpRequest(pkt)
			elif pkt[ARP].op == ARP_OP_REPLY:
				self.handleArpReply(pkt)
		elif Pwospf in pkt:
			self.handlePwospf(pkt)


	def send(self, *args, **override_kwargs):
		pkt = args[0]
		assert CPUMetadata in pkt, "Controller must send packets with special header"
		pkt[CPUMetadata].fromCpu = 1
		kwargs = dict(iface=self.iface, verbose=False)
		kwargs.update(override_kwargs)
		sendp(*args, **kwargs)

	def run(self):
		# TODO: Change the range so that every port (except 1) will have own hello msg sender
		helloPktList = []
		for i in range(2, 3): # To port 3
			#TODO: Checksum aint right
                	helloPktList.append(Ether()/CPUMetadata(fromCpu=1, origEtherType=0x800)/IP(src=self.pwospf_intfs[i].ip, dst='224.0.0.5', proto=89)/Pwospf(type=1, length=32, routerId=self.routerId, areaId=self.areaId, checksum=0)/Hello(networkMask=self.pwospf_intfs[i].mask, helloInt=self.pwospf_intfs[i].helloint))
		#helloPktList[0].show2()

		# TODO: Change the range so that every port (except 1) will have own hello msg sender
		self._helloSenderList.append(PeriodicSenderThread(sw=self.sw, pkt=helloPktList[0], interval=10))
		self._helloSenderList[0].start()
		sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event)

	def start(self, *args, **kwargs):
		super(MacLearningController, self).start(*args, **kwargs)
		time.sleep(self.start_wait)

	def join(self, *args, **kwargs):
		for i in range(len(self._helloSenderList)):
			self._helloSenderList[i].join(*args, **kwargs)
		self.stop_event.set()
		super(MacLearningController, self).join(*args, **kwargs)
