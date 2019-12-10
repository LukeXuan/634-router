from p4app import P4Mininet
from my_topo import SingleSwitchTopo
from controller import RouterController as Router
import time

# Add three hosts. Port 1 (h1) is reserved for the CPU.
N = 3

topo = SingleSwitchTopo(N)
net = P4Mininet(program='router.p4', topo=topo, auto_arp=False)
net.start()

# Add a mcast group for all ports (except for the CPU port)
sw1, sw2, sw3 = net.get('s1'), net.get('s2'), net.get('s3')

# Send MAC bcast packets to the bcast multicast group
cpu1 = Router(sw1, {
    2: {
        'subnet': "10.0.2.0/24",
        'ipaddr': '10.0.2.0',
        'helloint': 1
    },
    3: {
        'subnet': "10.0.3.0/24",
        'ipaddr': '10.0.3.0',
        'helloint': 1
    },
    4: {
        'subnet': "20.0.0.0/24",
        'ipaddr': '20.0.0.1',
        'helloint': 1
    }
})
cpu1.start()
cpu2 = Router(sw2, {
    2: {
        'subnet': "10.0.102.0/24",
        'ipaddr': '10.0.102.0',
        'helloint': 1
    },
    3: {
        'subnet': "10.0.103.0/24",
        'ipaddr': '10.0.103.0',
        'helloint': 1
    },
    4: {
        'subnet': "30.0.0.0/24",
        'ipaddr': '30.0.0.1',
        'helloint': 1
    }
})
cpu2.start()

cpu3 = Router(sw3, {
    2: {
        'subnet': "20.0.0.0/24",
        'ipaddr': '20.0.0.2',
        'helloint': 1
    },
    3: {
        'subnet': "30.0.0.0/24",
        'ipaddr': '30.0.0.2',
        'helloint': 1
    }
})

cpu3.start()

h2, h3 = net.get('h1_2'), net.get('h1_3')

# print h2.cmd('arping -c1 -w10 10.0.3.1')
# print(h3.cmd('ping -c1 10.0.2.1'))
print(h2.cmd('ping -c1 10.0.103.1'))


# These table entries were added by the CPU:
while True:
    time.sleep(5)
    sw1.printTableEntries()
    sw2.printTableEntries()
