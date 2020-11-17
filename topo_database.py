import time
import collections
from threading import RLock
from timeout_checker import TimeoutChecker
from scapy.all import Packet
from pwospf import Pwospf, LSU, LSUAd

RouterMetadata = collections.namedtuple('RouterMetadata', ['subnet', 'mask'])
EntryData = collections.namedtuple('EntryData', ['expiration', 'isValid'])

class TopoDatabase():
	def __init__(self, routerId, lsuInt, neighborInfo, sw):
		#self._routerList = set()
		self._databaseLock = RLock()
		self._routerList = {}
		self._database = {}
		self._routerId = routerId
		self._lsuInt = lsuInt
		self.sw = sw
		self._pathAdded = set()  # P4 currently lacks capability to modify table entries, once a route is set, add to the set, this route should not be modified anymore
		self._timeoutChecker = TimeoutChecker(self, lsuInt)
		#self._timeoutChecker.start() # Start the timeout sender #TODO: Renable this
		self.neighborInfo = neighborInfo

	def convertIPtoSubnet(self, ip, mask):
		#print('converting!')
		ipComponents = ip.split('.')
		maskComponents = mask.split('.')
		subnetComponents = []
		for i in range(4):
			subnetComponents.append(str(int(ipComponents[i]) & int(maskComponents[i])))	
		subnet = '.'.join(subnetComponents)
		#print(ip + '->' + subnet)
		return subnet
		

	def updateLink(self, fromRouter, toRouterList, ip, mask):
		subnet = self.convertIPtoSubnet(ip, mask)
		self._databaseLock.acquire()
		if(fromRouter not in self._database):
			self._database[fromRouter] = {}
		self._routerList[fromRouter] = RouterMetadata(subnet, mask)

		needToUpdate = False
		currTime = time.time()
		expireTime = currTime + self._lsuInt * 3
		for toRouter in toRouterList:
			#print('im updating shit')
			if(toRouter not in self._database):
				self._database[toRouter] = {}
		
			#print(str(self._routerId) + '. ' + str(fromRouter) + '->' + str(toRouter))
			if(fromRouter in self._database[toRouter]): # If toRouter already requested link to fromRouter, establish link
				toRouterMetaData = self._routerList[toRouter]
				if(toRouterMetaData.mask == mask):
					self._database[fromRouter][toRouter] = EntryData(expireTime, True)
					if(not self._database[toRouter][fromRouter].isValid): # Only establish for other router, if link is not currently established
						savedExpiration = self._database[toRouter][fromRouter].expiration
						self._database[toRouter][fromRouter] = EntryData(savedExpiration, True)
						needToUpdate = True
			else: # Else, establish intent to link between fromRouter and toRouter
				print('link request established')
				self._database[fromRouter][toRouter] = EntryData(expireTime, False)

		if(needToUpdate):
			self.updatePathing()
		self._databaseLock.release()


	# Determine which port to take to reach each topo connected subnet
	def updatePathing(self):
		# Implemented through BFS as each possible hop has equal weight
		print('Database updated!')
		visited = set()
		visited.add(self._routerId)

		# Best port to each neighbor of the current router is the port connecting to the neighbor
		bestPort = {}
		startQueue = []
		for routerId in self._database[self._routerId].keys():
			if(self._database[self._routerId][routerId].isValid):
				#print(routerId)
				bestPort[routerId] = routerId 
				visited.add(routerId)
				startQueue.append(routerId)

		#numRoutePorts = len(self._database[self._routerId].keys())
		queue = collections.deque(startQueue)
		while(queue):
			#print(queue)
			currRouterId = queue.popleft()
			currBestPort = bestPort[currRouterId]
			for neighborRouter in self._database[currRouterId].keys():
				if(neighborRouter not in visited and self._database[currRouterId][neighborRouter].isValid):
					visited.add(neighborRouter)
					bestPort[neighborRouter] = currBestPort
					queue.append(neighborRouter)
			
		# TODO: Update the routing table	
		# TODO: Reset the next lsu message send time
		# TODO: Leave mac address  = 0, just set port is all you need
		# bestPort is a dictionary containing the best port (neighbor port) to take to each router/subnet
		print('Database for router ' + str(self._routerId))	
		for key in bestPort.keys():
			if(key not in self._pathAdded):
				self._pathAdded.add(key)
				self.sw.insertTableEntry(table_name = 'MyIngress.fwd_ip', match_fields = {'hdr.ipv4.dstAddr': [self._routerList[key].subnet, 24]}, action_name = 'MyIngress.ipv4_fwd', action_params = {'mac': '00:00:00:00:00:00', 'port': self.neighborInfo[bestPort[key]]})

			#else:
			#	pass #TODO: add to table
			print(str(key) + ": " + str(bestPort[key]))
		#print(self._pathAdded)
			

	def removeLink(self, links):
		if not links:
			return

		self._databaseLock.acquire()
		needToUpdate = False
		for (fromRouter, toRouter) in links:
			assert fromRouter in self._database
			assert toRouter in self._database
			if(toRouter in self._database[fromRouter]):
				if(self._database[fromRouter][toRouter].isValid):
					expireTime = self._database[toRouter][fromRouter].expiration
					self._database[toRouter][fromRouter] = EntryData(expireTime, False)
					needToUpdate = True
				print('Deleted: ' + str(fromRouter) + ' -> ' + str(toRouter))
				del self._database[fromRouter][toRouter]
		if(needToUpdate):
			self.updatePathing()
		self._databaseLock.release()

	def checkExpireTimes(self):
		self._databaseLock.acquire()
		deleteList = []
		for fromRouter in self._database.keys():
			for toRouter in self._database[fromRouter].keys():
				if(self._database[fromRouter][toRouter].expiration  < time.time()):
					deleteList.append((fromRouter, toRouter))
		self.removeLink(deleteList)
		self._databaseLock.release()
	
	def handleLSUPkt(self, pkt):
		#print('handling packet!')
		numLSU = pkt[LSU].numAds
		assert numLSU

		pktRouter = pkt[Pwospf].routerId
		lsuList = pkt[LSU].lsuAdList
		pktIP = lsuList[0].subnet
		pktMask = lsuList[0].mask
		linkRouters = []
		#pkt.show2()
		for lsuAd in lsuList:
			linkRouters.append(lsuAd.routerId)

		self.updateLink(pktRouter, linkRouters, pktIP, pktMask)
		
		
#newDatabase = TopoDatabase(1, 3)	
#print('1.')
#newDatabase.updateLink(1,[7,2])
#newDatabase.updateLink(7,[1])
#newDatabase.updateLink(1, [5])
#print('2.')
#newDatabase.updateLink(2, [1])
#print('3.')
#newDatabase.updateLink(2, [3])
#newDatabase.updateLink(3, [2])
#print('4.')
#newDatabase.updateLink(6, [2])
#newDatabase.updateLink(2, [6])
#print('5.')
#newDatabase.updateLink(3, [5])
#newDatabase.updateLink(5, [3])
#print('6.')
#newDatabase.updateLink(6, [5])
#newDatabase.updateLink(5, [6])
#print('7.')
#newDatabase.updateLink(1, [6])
#newDatabase.updateLink(6,[1])
#print('8.')
#newDatabase.removeLink([(1, 6)])
#print('9.')
#newDatabase.updateLink(1, [6])
#print('10.')
#newDatabase.updateLink(2, [4])
#newDatabase.updateLink(4, [2])
#print('11.')
#newDatabase.updateLink(3, [4])
#newDatabase.updateLink(4, [3])
#print(10)

#time.sleep(30)
