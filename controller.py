from threading import Thread, Event, Timer
from scapy.all import sendp
from scapy.all import Packet, Ether, IP, ARP, Raw
from async_sniff import sniff
from cpu_metadata import CPUMetadata
from pwospf import *
from ipaddr import IPv4Address, IPv4Network
import config
import time

ARP_OP_REQ   = 0x0001
ARP_OP_REPLY = 0x0002
ETHER_ARP    = 0x0806
ETHER_IP     = 0x0800

NOREASON         = 0x0
REASON_ARP       = 0x1
REASON_PWOSPF    = 0x2
REASON_IP_FAIL   = 0x3
REASON_MAC_FAIL  = 0x4
REASON_PORT_FAIL = 0x5
REASON_UNKNOWN   = 0xff

TYPE_OSPF = 89
ETHER_BROADCAST = "ff:ff:ff:ff:ff:ff"
OSPF_BROADCAST = "224.0.0.5"

class PWOSPF:
    def __init__(self, ifaces, sw):
        self.ifaces = {}
        self.sw = sw
        self.id = ifaces["2"]['ipaddr']
        self.edges = {}
        self.root = {}
        self.dist = {}
        self.port_for_router = {}
        self.routers_for_subnet = {}
        self.next_hop_for_subnet = {}
        self.lsuint = 0
        self.seq = 0
        self.seq_for_router = {}
        self.subnets = set()
        for port, iface in ifaces.items():
            port = int(port)
            self.ifaces[port] = {
                'ipaddr': IPv4Address(iface['ipaddr']),
                'subnet': IPv4Network(iface['subnet']),
                'helloint': iface['helloint']
            }

            self.subnets.add(IPv4Network(iface['subnet']))
            ip = IPv4Address(iface['ipaddr'])
            subnet_ip = IPv4Network(iface['subnet']).ip
            prefixlen = self.ifaces[port]['subnet'].prefixlen
            self.sw.insertTableEntry(table_name='MyIngress.next_hop_ip_table',
                                     match_fields={'hdr.ip.dstAddr': [str(subnet_ip), prefixlen]},
                                     action_name='MyIngress.ipv4_direct')

            self.sw.insertTableEntry(table_name='MyIngress.mac_lookup_table',
                                     match_fields={'meta.next_hop_ip': [str(ip)]},
                                     action_name='MyIngress.mac_forward',
                                     action_params={'dstAddr': sw.intfs[1].MAC(), 'egress_port': 1})

    def in_subnet(self, port, ip):
        if isinstance(ip, str):
            ip = IPv4Address(ip)
        return ip in self.ifaces[port]['subnet']

    def port_for_ip(self, ip):
        if isinstance(ip, str):
            ip = IPv4Address(ip)
        for port, iface in self.ifaces.items():
            if ip in iface['subnet']:
                return port
        for router, port in self.port_for_router.items():
            if IPv4Address(router) == ip:
                return port
        return None

    def __getitem__(self, port):
        return self.ifaces[port]

    def hello_packet(self, port):
        return (Ether(dst=ETHER_BROADCAST)/
                CPUMetadata(origEtherType=ETHER_IP)/
                IP(src=str(self[port]['ipaddr']), dst=OSPF_BROADCAST, proto=TYPE_OSPF)/
                OSPF(routerID=self.id, areaID=config.areaID)/
                OSPFHello(mask=str(self[port]['subnet'].netmask), helloint=self[port]['helloint']))

    def link_state_packet(self, port, router):
        ipaddr = str(self.ifaces[port]['subnet'].ip)
        mask = str(self.ifaces[port]['subnet'].netmask)
        if router is None:
            router = "0.0.0.0"
        return OSPFLink(subnet=ipaddr, mask=mask, routerID=router)

    def broadcast_link_state(self, send):
        link_states = []
        included_ports = set()
        for router, port in self.port_for_router.items():
            included_ports.add(port)
            link_states.append(self.link_state_packet(port, router))
        for port in self.ifaces:
            if port not in included_ports:
                link_states.append(self.link_state_packet(port, None))

        packet = (Ether(dst=ETHER_BROADCAST)/
                  CPUMetadata(origEtherType=ETHER_IP)/
                  IP(src=self.id, dst=OSPF_BROADCAST, proto=TYPE_OSPF)/
                  OSPF(routerID=self.id, areaID=config.areaID)/
                  OSPFLSU(seq=self.seq, linklists=link_states))
        send(packet)
        self.lsuint = 1
        self.seq += 1

    def update_forward_map(self):
        for subnet, routers in self.routers_for_subnet.items():
            if subnet in self.subnets:
                continue
            if len(routers) == 0 and subnet in self.next_hop_for_subnet.items():
                ip = subnet.ip
                prefixlen = subnet.prefixlen
                print("%s: removing entry for %s/%d" % (self.id, ip, prefixlen))
                self.sw.deleteTableEntry(table_name='MyIngress.next_hop_ip_table',
                                         match_fields={'hdr.ip.dstAddr': [str(ip), prefixlen]},
                                         action_name='MyIngress.set_next_hop')
                self.sw.insertTableEntry(table_name='MyIngress.next_hop_ip_table',
                                         match_fields={'hdr.ip.dstAddr': [str(ip), prefixlen]},
                                         action_name='MyIngress.send_to_cpu',
                                         action_params={'reason': REASON_IP_FAIL})
                del self.next_hop_for_subnet
            else:
                router = max(routers, key=lambda router:-self.dist[router] if router in self.dist else 0)
                if router not in self.dist:
                    return
                root = self.root[router]
                if subnet not in self.next_hop_for_subnet or root != self.next_hop_for_subnet[subnet]:
                    ip = subnet.ip
                    prefixlen = subnet.prefixlen
                    print("%s: updating entry for %s/%d with next hop %s" % (self.id, ip, prefixlen, root))
                    if subnet in self.next_hop_for_subnet:
                        self.sw.deleteTableEntry(table_name='MyIngress.next_hop_ip_table',
                                                 match_fields={'hdr.ip.dstAddr': [str(ip), prefixlen]},
                                                 action_name='MyIngress.set_next_hop')
                    self.sw.insertTableEntry(table_name='MyIngress.next_hop_ip_table',
                                             match_fields={'hdr.ip.dstAddr': [str(ip), prefixlen]},
                                             action_name='MyIngress.set_next_hop',
                                             action_params={'next_hop_ip': root})
                    self.next_hop_for_subnet[subnet] = root

    def update_root_and_dist(self):
        working_set = set()
        visited_set = set()
        self.root = {}
        self.dist = {}
        for router in self.port_for_router:
            working_set.add(router)
            visited_set.add(router)
            self.root[router] = router
            self.dist[router] = 1

        while len(working_set) != 0:
            router = working_set.pop()
            root = self.root[router]
            dist = self.dist[router]
            if router not in self.edges:
                continue
            for r in self.edges[router]:
                if r not in visited_set:
                    visited_set.add(r)
                    working_set.add(r)
                    self.root[r] = root
                    self.dist[r] = dist + 1

    def update_adj(self, router, port, send):
        if (router not in self.port_for_router):
            self.port_for_router[router] = port
            self.broadcast_link_state(send)
        self.update_root_and_dist()
        self.update_forward_map()

    def update_link_state(self, pkt):
        router = pkt[OSPF].routerID
        # print("received update from %s" % router)
        if router in self.seq_for_router and self.seq_for_router[router] >= pkt[OSPFLSU].seq:
            return
        else:
            self.seq_for_router[router] = pkt[OSPFLSU].seq
        link_states = pkt[OSPFLSU].linklists
        self.edges[router] = set()
        for link_state in link_states:
            subnet = IPv4Network("%s/%s" % (link_state.subnet, link_state.mask))
            if subnet not in self.routers_for_subnet:
                self.routers_for_subnet[subnet] = set()

            # print("router %s is linked to %s" % (router, subnet))
            self.routers_for_subnet[subnet].add(router)
            if link_state.routerID != "0.0.0.0":
                self.edges[router].add(link_state.routerID)
        self.update_root_and_dist()
        self.update_forward_map()

class RouterController(Thread):
    def __init__(self, sw, ifaces, start_wait=0.3):
        super(RouterController, self).__init__()
        self.sw = sw
        self.start_wait = start_wait # time to wait for the controller to be listenning
        self.iface = sw.intfs[1].name
        self.mac_for_ip = {}
        self.port_for_mac = {}
        self.stop_event = Event()

        self.missing_ip_packets = set()
        self.missing_mac_packets = set()
        self.monitor = {}
        self.counter = 0

        bcast_mgid = 1
        sw.addMulticastGroup(mgid=bcast_mgid, ports=range(2, len(ifaces)+2))
        sw.insertTableEntry(table_name='MyIngress.next_hop_ip_table',
                            match_fields={'hdr.ip.dstAddr': ["224.0.0.5", 32]},
                            action_name='MyIngress.ipv4_direct')
        sw.insertTableEntry(table_name='MyIngress.mac_lookup_table',
                             match_fields={'meta.next_hop_ip': ["224.0.0.5"]},
                             action_name='MyIngress.set_mgid',
                             action_params={'mgid': bcast_mgid})
        sw.insertTableEntry(table_name='MyIngress.port_lookup_table',
                             match_fields={'hdr.ethernet.dstAddr': ["ff:ff:ff:ff:ff:ff"]},
                             action_name='NoAction')

        self.pwospf = PWOSPF(ifaces, sw)
        self.LSUINT = 30

    def addMacAddr(self, ip, mac, port):
        if ip in self.mac_for_ip: return

        self.sw.insertTableEntry(table_name='MyIngress.mac_lookup_table',
                match_fields={'meta.next_hop_ip': [ip]},
                action_name='MyIngress.mac_forward',
                action_params={'dstAddr': mac, 'egress_port': port})
        self.mac_for_ip[ip] = mac


        for pkt in set(self.missing_mac_packets):
            if pkt[CPUMetadata].nextHopIP == ip:
                print("%s: one packet from (%s) missing next hop (%s) Mac sent" % (self.pwospf.id, pkt[IP].src, pkt[CPUMetadata].nextHopIP))
                self.send(pkt)
                self.missing_mac_packets.remove(pkt)

    def addPort(self, mac, port):
        if mac in self.port_for_mac: return

        self.sw.insertTableEntry(table_name='MyIngress.port_lookup_table',
                match_fields={'hdr.ethernet.dstAddr': [mac]},
                action_name='MyIngress.port_forward',
                action_params={'egress_port': port})
        self.port_for_mac[mac] = port

    def handleArpReply(self, pkt):
        self.addMacAddr(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addPort(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)

    def handleArpRequest(self, pkt):
        self.addMacAddr(pkt[ARP].psrc, pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)
        self.addPort(pkt[ARP].hwsrc, pkt[CPUMetadata].srcPort)

        # if the ARP request is looking for host outside its subnet
        # we should reply our own mac
        if not self.pwospf.in_subnet(pkt[CPUMetadata].srcPort, pkt[ARP].pdst):
            packet = (
                Ether(dst=pkt[ARP].hwsrc)/
                CPUMetadata(origEtherType=ETHER_ARP) /
                ARP(op=ARP_OP_REPLY, hwsrc=self.sw.intfs[pkt[CPUMetadata].srcPort].MAC(),
                    psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc))
            self.send(packet)
        elif pkt[ARP].pdst == str(self.pwospf[pkt[CPUMetadata].srcPort]['ipaddr']):
            packet = (
                Ether(dst=pkt[ARP].hwsrc)/
                CPUMetadata(origEtherType=ETHER_ARP) /
                ARP(op=ARP_OP_REPLY, hwsrc=self.sw.intfs[pkt[CPUMetadata].srcPort].MAC(),
                    psrc=pkt[ARP].pdst, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc))
            self.send(packet)

    def handleOSPFPacket(self, pkt):
        ospf_layer = OSPF(pkt[Raw])
        pkt[IP].remove_payload()
        pkt = pkt/ospf_layer
        if OSPFHello in pkt:
            port = pkt[CPUMetadata].srcPort
            if (self.pwospf.in_subnet(port, pkt[IP].src) and
                str(self.pwospf[port]['subnet'].netmask) == pkt[OSPFHello].mask):
                self.pwospf.update_adj(pkt[OSPF].routerID, port, self.send)
                self.monitor[pkt[OSPF].routerID] = (port, 0, pkt[OSPFHello].helloint * 3)
            else:
                # print("OSPF subnet mismatch, ignored")
                pass
        elif OSPFLSU in pkt:
            self.pwospf.update_link_state(pkt)
            self.checkMissingIPPackets()
            if pkt[OSPFLSU].ttl > 0:
                pkt[OSPFLSU].ttl -= 1
                self.send(pkt)

    def checkMissingIPPackets(self):
        for pkt in set(self.missing_ip_packets):
            ip = IPv4Address(pkt[IP].dst)
            for subnet in self.pwospf.next_hop_for_subnet:
                if ip in subnet:
                    print("%s: one packet missing next hop IP sent" % self.pwospf.id)
                    self.send(pkt)
                    self.missing_ip_packets.remove(pkt)

    def heartbeat(self):
        for port in self.pwospf.ifaces:
            if self.counter % self.pwospf[port]['helloint'] == 0:
                self.send(self.pwospf.hello_packet(port))
        for routerID, (port, counter, timeout) in self.monitor.items():
            if counter > timeout:
                self.pwospf.remove_adj(routerID, port, self.send)

        self.counter += 1
        if self.pwospf.lsuint % self.LSUINT == 0:
            self.pwospf.broadcast_link_state(self.send)
        self.pwospf.lsuint += 1

    def handleMissingMacPacket(self, pkt):
        self.missing_mac_packets.add(pkt)
        # issue ARP request for the IP
        next_hop_ip = pkt[CPUMetadata].nextHopIP
        next_hop_port = self.pwospf.port_for_ip(next_hop_ip)

        print("%s: one packet from (%s) missing next hop (%s) Mac received" % (self.pwospf.id, pkt[IP].src, next_hop_ip))

        packet = (
                Ether(dst=ETHER_BROADCAST)/
                CPUMetadata(origEtherType=ETHER_ARP, dstPort=next_hop_port) /
                ARP(op=ARP_OP_REQ,
                    hwsrc=self.sw.intfs[next_hop_port].MAC(),
                    psrc=str(self.pwospf[next_hop_port]['ipaddr']),
                    hwdst=ETHER_BROADCAST, pdst=next_hop_ip))

        self.send(packet)

    def handleMissingIPPacket(self, pkt):
        print("%s: one packet missing next hop IP received" % self.pwospf.id)
        self.missing_ip_packets.add(pkt)

    def proper_pkt(self, pkt):
        if CPUMetadata in pkt:
            return True
        if IP in pkt:
            port = self.pwospf.port_for_ip(pkt[IP].dst)
            if port != None and pkt[IP].dst == str(self.pwospf[port]['ipaddr']):
                return True
            print("%s: received improper packet %s" % (self.pwospf.id, pkt[IP].dst))
        return False

    def handlePkt(self, pkt):
        if not self.proper_pkt(pkt):
            pkt.show2()
            print('Should only receive packets from switch with special header')
            assert False

        if CPUMetadata not in pkt:
            print("received packet for the router's IP %s" % pkt[IP].dst)
            return

        # Ignore packets that the CPU sends:
        if pkt[CPUMetadata].fromCpu == 1: return

        if pkt[CPUMetadata].reason == REASON_UNKNOWN:
            pkt.show2()
            print('Unknown protocol')
            assert False

        if pkt[CPUMetadata].reason == REASON_ARP:
            if pkt[ARP].op == ARP_OP_REQ:
                self.handleArpRequest(pkt)
            elif pkt[ARP].op == ARP_OP_REPLY:
                self.handleArpReply(pkt)
        elif pkt[CPUMetadata].reason == REASON_PWOSPF:
            self.handleOSPFPacket(pkt)
        elif pkt[CPUMetadata].reason == REASON_PORT_FAIL:
            pkt.show2()
            assert False, "should never happen"
        elif pkt[CPUMetadata].reason == REASON_MAC_FAIL:
            self.handleMissingMacPacket(pkt)
        elif pkt[CPUMetadata].reason == REASON_IP_FAIL:
            self.handleMissingIPPacket(pkt)

    def send(self, *args, **override_kwargs):
        pkt = args[0]
        assert CPUMetadata in pkt, 'Controller must send packets with special header'
        pkt[CPUMetadata].fromCpu = 1
        kwargs = dict(iface=self.iface, verbose=False)
        kwargs.update(override_kwargs)
        sendp(*args, **kwargs)

    def run(self):
        sniff(iface=self.iface, prn=self.handlePkt, stop_event=self.stop_event, hb=self.heartbeat)

    def start(self, *args, **kwargs):
        super(RouterController, self).start(*args, **kwargs)

    def join(self, *args, **kwargs):
        self.stop_event.set()
        super(RouterController, self).join(*args, **kwargs)
