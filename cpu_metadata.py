from scapy.fields import BitField, ByteField, ShortField, IPField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP

TYPE_CPU_METADATA = 0x081a

class CPUMetadata(Packet):
    name = "CPUMetadata"
    fields_desc = [ ByteField("fromCpu", 1),
                    ShortField("origEtherType", None),
                    ShortField("srcPort", 0),
                    ShortField("dstPort", 0),
                    IPField("nextHopIP", "127.0.0.1"),
                    ByteField("reason", 0)]

bind_layers(Ether, CPUMetadata, type=TYPE_CPU_METADATA)
bind_layers(CPUMetadata, IP, origEtherType=0x0800)
bind_layers(CPUMetadata, ARP, origEtherType=0x0806)
