#from globalNames import Pwospf_intf, Pwospf_neighbor, MAX_INTF
from scapy.all import Packet, Ether, IP, ARP
from cpu_metadata import CPUMetadata 
from periodic_send import PeriodicSenderThread, PeriodicLSUSenderThread
from pwospf import Pwospf, Hello, LSU, LSUAd
from collections import namedtuple
from timeout_checker import TimeoutChecker
from threading import Lock
import time
import copy

Pwospf_intf = namedtuple('Pwospf_intf', ['ip', 'mask', 'helloint', 'neighbors'])
Pwospf_neighbor = namedtuple('Pwospf_neighbor', ['id', 'ip'])

MAX_INTF = 8

class PwospfIntf():
	def __init__(self, sw, routerId, areaId, lsuint, database, neighborInfo):
	        # PWOSPF Interface Setup 
		self.sw = sw
		self.routerId = routerId
		self.areaId = areaId
		self.database = database
		self.intfLock = Lock()
                self.pwospf_intfs = []
		self.neighborInfo = neighborInfo
                #TODO: Need to exclude adding interface 1, should never send back to CPU, or maybe not -> currently just not sending hello packets on this intf
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

		# Initialize hello timeout checkers
		checkInterval = 30
		self._timeoutChecker = TimeoutChecker(self, checkInterval)

		# Initialize periodic lsu pkt sender
		self.lsuSeqNum = 0 
		self._lsuSender = PeriodicLSUSenderThread(sw, self, lsuint) 

	def handleHelloPkt(self, pkt):
		#print('Got a packet!')
                srcPort = pkt[CPUMetadata].srcPort 
                intf = self.pwospf_intfs[srcPort - 1] 
                if(pkt[Hello].networkMask != intf.mask): return 
                if(pkt[Hello].helloInt != intf.helloint): return 

                pktRouterId = pkt[Pwospf].routerId
                srcIP = pkt[IP].src;
		expireTime = time.time() + intf.helloint * 3
		#expireTime = 0  # TODO: Recomment this
		#print(expireTime)
		
		needToUpdate = False
		self.intfLock.acquire()
                if srcIP not in intf.neighbors:
			needToUpdate = True
                        intf.neighbors[srcIP] = [pktRouterId, expireTime] #TODO: What if duplicate? If IP changes, then needs to signal update on topo?
			self.neighborInfo[pktRouterId] = srcPort
			print('Router ' + str(self.routerId) + ' added: ')
                        print(srcIP, pktRouterId)
                else:
                        # Update Last Hello Packet Received Timer 
			intf.neighbors[srcIP][1] = expireTime
		self.intfLock.release()

		if needToUpdate:
			self.database.updateLink(self.routerId, [pktRouterId], intf.ip, intf.mask)
			#TODO: Signal to sender thread that update is needed and reset timer
		#TODO: INFO: PKTS (HELLO AND LSU) CAN ONLY ADD NEW SEGMENTS, TIMERS (FOR LSU AND HELLO) CAN ONLY REMOVE SEGMENTS
	
	def checkExpireTimes(self):
		print('Running check!')
		willRemove = []
		currTime = time.time()
		#print(currTime)

		self.intfLock.acquire()
		for intfIndex in range(0, MAX_INTF):
			intf = self.pwospf_intfs[intfIndex]
			for srcIP in intf.neighbors.keys():
				expireTime = intf.neighbors[srcIP][1] # Second entry lists the expiration time of the entry
				if(currTime > expireTime):
					neighborRouterId = intf.neighbors[srcIP][0]
					willRemove.append((intfIndex, srcIP, neighborRouterId))
		
		toRemoveList = self.timeoutNeighbor(willRemove)
		self.intfLock.release()

		# TODO: Signal change to lsu sender
		self.database.removeLink(toRemoveList)
				
	
	def timeoutNeighbor(self, removeList):
		toRemoveList = []
		for (intfId, srcIP, neighborRouterId) in removeList:
			print('Router ' + str(self.routerId) + ' removed ip, id: ')
			print(srcIP, neighborRouterId)
			toRemoveList.append((self.routerId, neighborRouterId))
			del self.pwospf_intfs[intfId].neighbors[srcIP]
		#database.removeLink(toRemoveList)
		return toRemoveList

	def getLSUPackets(self):
		self.intfLock.acquire()
		LSUlist = []
		for intf in self.pwospf_intfs:
			for neighborIP in intf.neighbors.keys():
				LSUlist.append(LSUAd(subnet=intf.ip, mask=intf.mask, routerId=intf.neighbors[neighborIP][0]))
				#LSUlist.append(LSUAd(subnet=intf.ip, mask=intf.mask, routerId=self.routerId)) # TODO: For test only, remove in production
		if not LSUlist:
			#print('No packets :(')
			self.intfLock.release()
			return None
		
		#print('Packets yay!')
		#TODO: Checksum is wrong
		numNeighbors = len(LSUlist)
		pktList = []
		for intf in self.pwospf_intfs:
			for neighborIP in intf.neighbors.keys():
				pktList.append(Ether()/CPUMetadata(fromCpu=1, origEtherType=0x800)/IP(src=intf.ip, dst=neighborIP, proto=89)/Pwospf(type=4, length=32 + numNeighbors * 12, routerId=self.routerId, areaId=self.areaId, checksum=0)/LSU(seq=self.lsuSeqNum, lsuAdList=LSUlist))
		self.lsuSeqNum += 1
		self.intfLock.release()
		
		return copy.deepcopy(pktList)

	def getFloodPacketList(self, pkt):
		self.intfLock.acquire()
		pktList = []
		receiveIP = pkt[IP].src
		for intf in self.pwospf_intfs:
			for neighborIP in intf.neighbors.keys():	
				if(neighborIP == receiveIP): continue #TODO: Uncomment this
				#TODO: Checksum is wrong
				pktList.append(Ether()/CPUMetadata(fromCpu=1, origEtherType=0x800)/IP(src=intf.ip, dst=neighborIP, proto=89)/Pwospf(type=4, length=pkt[Pwospf].length, routerId=pkt[Pwospf].routerId, areaId=pkt[Pwospf].areaId, checksum=0)/LSU(seq=pkt[LSU].seq, ttl=pkt[LSU].ttl, lsuAdList=pkt[LSU].lsuAdList))
				
		self.intfLock.release()
		if not pktList:
			return None
		return copy.deepcopy(pktList)


	def startIntfSenders(self):
		#TODO: Change this back
		#for i in range(0, MAX_INTF): # Start up hello senders for each port except 1 
		for i in range(1, 3):
                	if(i == 0): 
                        	continue 
                        else: 
                                self._helloSenderList[i].start()
		#self._timeoutChecker.start() # TODO: Renable this
		self._lsuSender.start()
