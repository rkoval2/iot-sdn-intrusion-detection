#!/usr/bin/python3.8
import time

from mininet.cli import CLI
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.node import RemoteController, Node


# Topology:
# h1 -> s1 <- h2
#   h3 -^
# Where s1 is an ethernet hub,
# h1 is a mosquitto server,
# h2 is a mosquitto subscriber,
# h3 is a mosquitto publisher

class Topology(Topo):
    def __init__(self):
        Topo.__init__(self)

        self.addHost("h1", mac="00:00:00:00:00:01", ip="10.0.0.1")
        self.addHost("h2", mac="00:00:00:00:00:02", ip="10.0.0.2")
        self.addHost("h3", mac="00:00:00:00:00:03", ip="10.0.0.3")
        self.addHost("h4", mac="00:00:00:00:00:04", ip="10.0.0.4")

        self.addSwitch("s1")

        self.addLink("h1", "s1")
        self.addLink("h2", "s1")
        self.addLink("h3", "s1")
        self.addLink("h4", "s1")


def main():
    topology = Topology()
    net = Mininet(topo=topology, controller=RemoteController)
    net.start()
    dumpNodeConnections(net.hosts)

    h1: Node = net.get("h1")
    h2: Node = net.get("h2")
    h3: Node = net.get("h3")

    h1.cmd("mosquitto -c mosquitto.conf &> /tmp/h1.out &")

    time.sleep(1)

    h2.cmd(f"mosquitto_sub -h {h1.IP()} -v -t 'test/topic' &> /tmp/h2.out &")

    time.sleep(1)

    # h3.cmd(
    #     f"mosquitto_pub -h {h1.IP()} -t 'test/topic' "
    #     f"-m '{{\"ts\":1701846050443,\"ts\":1701846050443,\"sensor\":0.058175915160029845}}'"
    # )

    h3.cmd(
        f"while true; do "
        f"mosquitto_pub -h {h1.IP()} -t 'test/topic' "
        '-m "{{\\"ts\\":\\"$(date -Iseconds)\\",\\"sensor\\":$RANDOM}}"; '
        f"sleep 0.5; "
        f"done &")

    CLI(net)

    h1.cmd("kill %mosquitto")
    h2.cmd("kill %mosquitto_sub")
    h3.cmd("kill %mosquitto_pub")

    net.stop()


if __name__ == "__main__":
    setLogLevel('info')
    main()
