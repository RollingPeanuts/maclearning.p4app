import time
import collections

class TopoDatabase():
	def __init__(self, routerId, lsuInt):
		self._routerList = set()
		self._database = {}
		self._routerId = routerId
		self._lsuInt = lsuInt

	def updateLink(self, fromRouter, toRouter = None):
		#TODO: Add a system where lsu needs confirmation from both sides -> aka, set self._database[toRouter][fromRouter] to infinite ? Then check mask? Then updatePathing needs to check each key to see if its infinite then ignore that basically...
		#TODO: Add locks
		# Might need lock around _routerList too
		assert fromRouter
		if(fromRouter not in self._routerList):
			self._routerList.add(fromRouter)
			self._database[fromRouter] = {}
		if(not toRouter):
			return
		if(toRouter not in self._routerList):
			self._routerList.add(toRouter)
			self._database[toRouter] = {}

		# If connection didn't exist before, need to update routing table
		#TODO: Lock here
		needToUpdate = False
		#if(toRouter not in self._database[fromRouter] or fromRouter not in self._database[toRouter]):
		if(toRouter not in self._database[fromRouter]):
			needToUpdate = True

		currTime = time.time() #Time in seconds
		expireTime = currTime + self._lsuInt * 3
		self._database[fromRouter][toRouter] = expireTime
		#self._database[toRouter][fromRouter] = expireTime
		
		if(needToUpdate):
			self.updatePathing()

	# Determine which port to take to reach each topo connected subnet
	def updatePathing(self):
		# Implemented through BFS as each possible hop has equal weight
		visited = set()
		visited.add(self._routerId)

		# Best port to each neighbor of the current router is the port connecting to the neighbor
		bestPort = {}
		for routerId in self._database[self._routerId].keys():
			bestPort[routerId] = routerId 
			visited.add(routerId)

		#numRoutePorts = len(self._database[self._routerId].keys())
		queue = collections.deque(self._database[self._routerId].keys())
		while(queue):
			currRouterId = queue.popleft()
			currBestPort = bestPort[currRouterId]
			for neighborRouter in self._database[currRouterId].keys():
				if(neighborRouter not in visited):
					bestPort[neighborRouter] = currBestPort
					visited.add(neighborRouter)
					queue.append(neighborRouter)
			
		# TODO: Update the routing table	
		# bestPort is a dictionary containing the best port (neighbor port) to take to each router/subnet
		for key in bestPort.keys():
     			print(str(key) + ": " + str(bestPort[key]))
			

	def removeLink(self, fromRouter, toRouter):
		# TODO: Add locks, identical to updatelock
		assert fromRouter in self._routerList		
		assert toRouter in self._routerList
		if(toRouter in self._database[fromRouter]):
			del self._database[fromRouter][toRouter]
			self.updatePathing()
		
		
newDatabase = TopoDatabase(1, 1)	
print(1)
newDatabase.updateLink(1, 7)
#newDatabase.updateLink(7, 1, 1)
print(2)
newDatabase.updateLink(1, 2)
#newDatabase.updateLink(2, 1, 1)
print(3)
newDatabase.updateLink(2, 3)
#newDatabase.updateLink(3, 2, 1)
print(4)
newDatabase.updateLink(6, 2)
#newDatabase.updateLink(2, 6, 1)
print(5)
newDatabase.updateLink(3, 5)
#newDatabase.updateLink(5, 3, 1)
print(6)
newDatabase.updateLink(6, 5)
#newDatabase.updateLink(5, 6, 1)
print(7)
newDatabase.updateLink(1, 6)
print(8)
newDatabase.removeLink(1, 6)
print(8)
newDatabase.updateLink(6, 1)
print(8)
newDatabase.updateLink(2, 4)
#newDatabase.updateLink(4, 2, 1)
print(9)
newDatabase.updateLink(3, 4)
#newDatabase.updateLink(4, 3, 1)
print(10)
