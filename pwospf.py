from scapy.fields import BitField, ByteField, ShortField, IntField, LongField, IPPrefixField, IPField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_PWOSPF = 0x59
PWOSPF_TYPE_HELLO = 0x01

class Pwospf(Packet):
    name = "Pwospf"
    fields_desc = [ ByteField("version", 2),
		    ByteField("type", None),
		    ShortField("length", None),
		    IntField("routerId", None),
		    IntField("areaId", None),
		    ShortField("checksum", None),
		    ShortField("auType", 0),
		    LongField("authentication", 0)]

bind_layers(IP, Pwospf, proto=TYPE_PWOSPF)

class Hello(Packet):
    name = "Hello"
    fields_desc = [ IPField("networkMask", None),
		    ShortField("helloInt", None),
		    ShortField("padding", 0)]

bind_layers(Pwospf, Hello, type=PWOSPF_TYPE_HELLO)

#bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
#bind_layers(CPUMetadata, IP, origEtherType=0x0800)
#bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
