from scapy.fields import BitField, ByteField, ShortField, IPField, IntField, PacketListField, FieldLenField, LenField, LongField
from scapy.packet import Packet, bind_layers
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether, ARP
from scapy.utils import checksum
from scapy.compat import chb

TYPE_OSPF = 89
TYPE_HELLO = 1
TYPE_LSU = 4

class OSPF(Packet):
    name = "OSPF"
    fields_desc = [ ByteField("version", 2),
                    ByteField("type", None),
                    ShortField("length", None),
                    IPField("routerID", None),
                    IntField("areaID", None),
                    ShortField("checksum", None),
                    ShortField("autype", 0),
                    LongField("authentication", 0)
    ]
    def post_build(self, p, pay):
        if self.length == None:
            ck = len(p + pay)
            p = p[:2] + chb(ck >> 8) + chb(ck & 0xff) + p[4:]
        if self.checksum == None:
            ck  = checksum(p + pay)
            p = p[:12] + chb(ck >> 8) + chb(ck & 0xff) + p[14:]
        return p + pay

class OSPFHello(Packet):
    name = "OSPFHello"
    fields_desc = [ IPField("mask", None),
                    ShortField("helloint", None),
                    ShortField("padding", None)
    ]

class OSPFLink(Packet):
    name = "OSPFLink"
    fields_desc = [ IPField("subnet", None),
                    IPField("mask", None),
                    IPField("routerID", None)
    ]

    def extract_padding(self, s):
        return '', s

class OSPFLSU(Packet):
    name = "OSPFLSU"
    fields_desc = [ ShortField("seq", 0),
                    ShortField("ttl", 3),
                    FieldLenField("num", None, count_of="linklists"),
                    PacketListField("linklists", None, OSPFLink,
                                    length_from=lambda pkt:pkt.num * 12)
    ]
    def extract_padding(self, s):
        return '', s

bind_layers(IP, OSPF, proto=TYPE_OSPF)
bind_layers(OSPF, OSPFHello, type=TYPE_HELLO)
bind_layers(OSPF, OSPFLSU, type=TYPE_LSU)
