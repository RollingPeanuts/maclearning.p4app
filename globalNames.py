from collections import namedtuple

#TYPE_PWOSPF = 0x59
#PWOSPF_TYPE_HELLO = 0x01
Pwospf_intf = namedtuple('Pwospf_intf', ['ip', 'mask', 'helloint', 'neighbors'])
Pwospf_neighbor = namedtuple('Pwospf_neighbor', ['id', 'ip'])

MAX_INTF = 8
