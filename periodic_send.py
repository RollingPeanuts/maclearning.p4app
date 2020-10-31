from threading import Thread, Event
from scapy.all import sendp
from scapy.all import Packet, Ether, IP
from cpu_metadata import CPUMetadata
import time

class PeriodicSenderThread(Thread):
	def __init__(self, sw, pkt, interval=0.5):
		# type: (Packet, float) -> None
		""" Thread to send packets periodically
		Args:
		pkt: packet to send
		interval: interval between two packets
		"""
		self._pkt = pkt
		self.sw = sw
                self.iface = sw.intfs[1].name
		#print("INTF: ", self.iface)
		# Not setting srcport
		#self._pkt = Ether()/CPUMetadata(fromCpu=1, origEtherType=0x800)/IP(dst='224.0.0.5', proto=89)/Pwospf(type=1, routerId=routerId, areaId=areaId)/Hello(networkMask=networkMask, helloInt=helloInt)
		self._stopped = Event()
		self._interval = interval
		self.start_wait = 0.3
		super(PeriodicSenderThread, self).__init__()

	def run(self):
		# TODO: Add a sleep before starting inorder to allow router packet sniffer to start running
		assert self._pkt, "Pkt cannot be empty"
		while not self._stopped.is_set():
			self.send(self._pkt)
			time.sleep(self._interval)

	def send(self, *args, **override_kwargs):
		pkt = args[0]
		assert CPUMetadata in pkt, "Controller must send packets with special header"
		pkt[CPUMetadata].fromCpu = 1
		#print("my send is being called")
		kwargs = dict(iface=self.iface, verbose=False)
		kwargs.update(override_kwargs)
		sendp(*args, **kwargs)

	#def stop(self):
		# type: () -> None
		#self._stopped.set()

        def start(self, *args, **kwargs):
                super(PeriodicSenderThread, self).start(*args, **kwargs)
                time.sleep(self.start_wait)

	def join(self, *args, **kwargs):
                self._stopped.set()
                super(PeriodicSenderThread, self).join(*args, **kwargs)
