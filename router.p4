/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

typedef bit<9>  port_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<16> mcastGrp_t;
typedef bit<8> reason_t;

const port_t CPU_PORT           = 0x1;

const bit<16> ARP_OP_REQ        = 0x0001;
const bit<16> ARP_OP_REPLY      = 0x0002;

const bit<16> TYPE_ARP          = 0x0806;
const bit<16> TYPE_CPU_METADATA = 0x080a;
const bit<16> TYPE_IP           = 0x0800;

const reason_t REASON_NO        = 0x0;
const reason_t REASON_ARP       = 0x1;
const reason_t REASON_PWOSPF    = 0x2;
const reason_t REASON_IP_FAIL   = 0x3;
const reason_t REASON_MAC_FAIL  = 0x4;
const reason_t REASON_PORT_FAIL = 0x5;
const reason_t REASON_UNKNOWN   = 0xff;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header cpu_metadata_t {
    bit<8> fromCpu;
    bit<16> origEtherType;
    bit<16> srcPort;
    bit<16> dstPort;
    ip4Addr_t nextHopIP;
    reason_t reason;
}

header arp_t {
    bit<16> hwType;
    bit<16> protoType;
    bit<8> hwAddrLen;
    bit<8> protoAddrLen;
    bit<16> opcode;
    // assumes hardware type is ethernet and protocol is IP
    macAddr_t srcEth;
    ip4Addr_t srcIP;
    macAddr_t dstEth;
    ip4Addr_t dstIP;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers {
    ethernet_t        ethernet;
    cpu_metadata_t    cpu_metadata;
    arp_t             arp;
    ipv4_t            ip;
}

struct metadata {
    ip4Addr_t         next_hop_ip;
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {
    state start {
        meta.next_hop_ip = 0;
        hdr.cpu_metadata.reason = REASON_NO;
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_ARP: parse_arp;
            TYPE_CPU_METADATA: parse_cpu_metadata;
            TYPE_IP: parse_ip;
            default: accept;
        }
    }

    state parse_cpu_metadata {
        packet.extract(hdr.cpu_metadata);
        transition select(hdr.cpu_metadata.origEtherType) {
            TYPE_ARP: parse_arp;
            TYPE_IP: parse_ip;
            default: accept;
        }
    }

    state parse_ip {
        packet.extract(hdr.ip);
        transition accept;
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
}

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

control MyIngress(inout headers hdr,
inout metadata meta,
inout standard_metadata_t standard_metadata) {
    counter(3, CounterType.packets) counters;
    action drop() {
        mark_to_drop();
    }

    action set_egr(port_t port) {
        standard_metadata.egress_spec = port;
    }

    action set_mgid(mcastGrp_t mgid) {
        standard_metadata.mcast_grp = mgid;
        hdr.ethernet.dstAddr = 0xffffffffffff;
    }

    action cpu_meta_encap(reason_t reason) {
        hdr.cpu_metadata.setValid();
        hdr.cpu_metadata.origEtherType = hdr.ethernet.etherType;
        hdr.cpu_metadata.srcPort = (bit<16>)standard_metadata.ingress_port;
        hdr.cpu_metadata.reason = reason;
        hdr.cpu_metadata.nextHopIP = meta.next_hop_ip;
        hdr.cpu_metadata.dstPort = 0;
        hdr.ethernet.etherType = TYPE_CPU_METADATA;
    }

    action cpu_meta_decap() {
        hdr.ethernet.etherType = hdr.cpu_metadata.origEtherType;
        standard_metadata.egress_spec = (bit<9>)hdr.cpu_metadata.dstPort;
        hdr.cpu_metadata.setInvalid();
    }

    action send_to_cpu(reason_t reason) {
        counters.count(0);
        cpu_meta_encap(reason);
        standard_metadata.egress_spec = CPU_PORT;
    }

    action set_next_hop(ip4Addr_t next_hop_ip) {
        meta.next_hop_ip = next_hop_ip;
    }

    action ipv4_direct() {
        meta.next_hop_ip = hdr.ip.dstAddr;
    }

    action mac_forward(macAddr_t dstAddr, port_t egress_port) {
        hdr.ethernet.dstAddr = dstAddr;
        standard_metadata.egress_spec = egress_port;
    }

    action port_forward(port_t egress_port) {
        standard_metadata.egress_spec = egress_port;
    }

    table next_hop_ip_table {
        key = {
            hdr.ip.dstAddr: lpm;
        }

        actions = {
            set_next_hop;
            ipv4_direct;
            send_to_cpu;
        }

        size = 1024;
        default_action = send_to_cpu(REASON_IP_FAIL);
    }

    table mac_lookup_table {
        key = {
            meta.next_hop_ip: exact;
        }

        actions = {
            mac_forward;
            set_mgid;
            send_to_cpu;
        }

        size = 1024;
        default_action = send_to_cpu(REASON_MAC_FAIL);
    }


    table port_lookup_table {
        key = {
            hdr.ethernet.dstAddr: exact;
        }

        actions = {
            port_forward;
            NoAction;
            send_to_cpu;
        }

        size = 1024;
        default_action = send_to_cpu(REASON_PORT_FAIL);
    }

    apply {

        if (standard_metadata.ingress_port == CPU_PORT)
        cpu_meta_decap();

        // The CPU should handle all incoming ARP packets
        if (hdr.arp.isValid() && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu(REASON_ARP);
        }

        else if (hdr.ip.isValid() && hdr.ip.protocol == 89 && standard_metadata.ingress_port != CPU_PORT) {
            send_to_cpu(REASON_PWOSPF);
        }
        else if (hdr.ip.isValid()) {
            counters.count(2);
            next_hop_ip_table.apply();
            if (! hdr.cpu_metadata.isValid()) {
                mac_lookup_table.apply();
            }
            if (!hdr.cpu_metadata.isValid()) {
               if (hdr.ip.ttl != 0) {
                   hdr.ip.ttl = hdr.ip.ttl - 1;
               } else {
                   drop();
               }
            }
        }
        else if (hdr.arp.isValid()) {
            counters.count(1);
            port_lookup_table.apply();
        }
        else {
            send_to_cpu(REASON_UNKNOWN);
        }
    }
}

control MyEgress(inout headers hdr,
inout metadata meta,
inout standard_metadata_t standard_metadata) {
    apply { }
}

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {
          update_checksum(
	        hdr.ip.isValid(),
          { hdr.ip.version,
	          hdr.ip.ihl,
            hdr.ip.diffserv,
            hdr.ip.totalLen,
            hdr.ip.identification,
            hdr.ip.flags,
            hdr.ip.fragOffset,
            hdr.ip.ttl,
            hdr.ip.protocol,
            hdr.ip.srcAddr,
            hdr.ip.dstAddr },
          hdr.ip.hdrChecksum,
          HashAlgorithm.csum16);
    }
}

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.cpu_metadata);
        packet.emit(hdr.arp);
        packet.emit(hdr.ip);
    }
}

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
