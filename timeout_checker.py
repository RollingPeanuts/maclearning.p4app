from threading import Thread, Event
import time

class TimeoutChecker(Thread):
	def __init__(self, intfList, interval):
		self.intfList = intfList
		self._stopped = Event()
		self._interval = interval
		self.start_wait = 0.3
		super(TimeoutChecker, self).__init__()
	
	def run(self):
		while not self._stopped.is_set():
			time.sleep(self._interval)
			self.intfList.checkExpireTimes()
	
	def start(self, *args, **kwargs):
		super(TimeoutChecker, self).start(*args, **kwargs)	
		time.sleep(self.start_wait)

	def join(self, *args, **kwargs):
                self._stopped.set()
                super(TimeoutChecker, self).join(*args, **kwargs)
