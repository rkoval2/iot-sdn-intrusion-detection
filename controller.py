import logging
from typing import Dict, Tuple

from ryu.base.app_manager import RyuApp
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, tcp, ipv4
from ryu.lib import hub

from monitor import Flag, Protocol, TcpConn, TcpConnState, TcpConnWindow, Land
from detect import Detector


def get_data_size(pkt_ip: ipv4.ipv4, pkt_tcp: tcp.tcp):
    return max(0, pkt_ip.total_length - (pkt_ip.header_length + pkt_tcp.offset) * 4)


class Controller(RyuApp):
    """
    Simple ethernet hub controller

    Switches transmit L2 frames to controller, and controller instructs switch
    to flood the frames out of all ports

    Reference code taken from https://github.com/faucetsdn/ryu/blob/master/ryu/app/simple_switch_13.py
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    open_conn: Dict[Tuple[str, int, str, int], TcpConn]
    window: TcpConnWindow

    def __init__(self, *args, **kwargs):
        super(Controller, self).__init__(*args, **kwargs)

        self.open_conn = {}
        self.blocked_hosts = set()
        self.window = TcpConnWindow()

        self.detector = Detector()

        self.logger.setLevel(logging.WARN)

        hub.spawn(self.monitor)

    def monitor(self):
        while True:
            stats = self.window.stats()
            for stat in stats:
                is_attack = self.detector.detect(stat)
                if is_attack and stat.conn.src_ip not in self.blocked_hosts:
                    self.logger.warn(
                        f"Detected attack: origin={stat.conn.src_ip}:{stat.conn.src_port}, "
                        f"dest={stat.conn.dst_ip}:{stat.conn.dst_port}, mitigating...")
                    self.blocked_hosts.add(stat.conn.src_ip)
            hub.sleep(2)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        """
        Switch features event handler

        Adds a flow entry instructing the switch to forward packets to this controller on a table-miss
        """
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        Incoming packet event handler

        Instructs the switch to flood the packet on all ports.
        If the packet contains a TCP segment, performs attack detection on it
        """

        ts = ev.timestamp
        msg = ev.msg
        datapath = msg.datapath
        ofproto = msg.datapath.ofproto
        parser = msg.datapath.ofproto_parser
        pck = packet.Packet(msg.data)

        pck_ip, pck_tcp = None, None

        for p in pck:
            if isinstance(p, bytes):
                break

            if p.protocol_name == "ipv4":
                pck_ip = p
            elif p.protocol_name == "tcp":
                pck_tcp = p
                break

        if pck_ip and pck_tcp:
            self.handle_tcp(pck_ip, pck_tcp, ts)

        if pck_ip and pck_ip.src in self.blocked_hosts:
            return

        in_port = msg.match['in_port']

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions):
        """
        Installs a flow entry on the given data path
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst)
        datapath.send_msg(mod)

    def remove_conn(self, pkt_ip: ipv4.ipv4, pkt_tcp: tcp.tcp):
        self.open_conn.pop((pkt_ip.src, pkt_tcp.src_port, pkt_ip.dst, pkt_tcp.dst_port), None)
        self.open_conn.pop((pkt_ip.dst, pkt_tcp.dst_port, pkt_ip.src, pkt_tcp.src_port), None)

    def set_conn(self, pkt_ip: ipv4.ipv4, pkt_tcp: tcp.tcp, conn: TcpConn):
        self.open_conn[(pkt_ip.src, pkt_tcp.src_port, pkt_ip.dst, pkt_tcp.dst_port)] = conn
        self.open_conn[(pkt_ip.dst, pkt_tcp.dst_port, pkt_ip.src, pkt_tcp.src_port)] = conn

    def has_conn(self, pkt_ip: ipv4.ipv4, pkt_tcp: tcp.tcp):
        return (pkt_ip.src, pkt_tcp.src_port, pkt_ip.dst, pkt_tcp.dst_port) in self.open_conn

    def get_conn(self, pkt_ip: ipv4.ipv4, pkt_tcp: tcp.tcp):
        return self.open_conn[(pkt_ip.src, pkt_tcp.src_port, pkt_ip.dst, pkt_tcp.dst_port)]

    def handle_state(self, conn: TcpConn, state: TcpConnState):
        if not self.logger.disabled:
            self.logger.info(
                f"State update {conn.src_ip}:{conn.src_port}->{conn.dst_ip}:{conn.dst_port}: {conn.state}->{state}")
        conn.state = state
        return conn

    def handle_close(self, conn: TcpConn, ts: float):
        if conn.end_ns != 0:
            return

        conn.end_ns = ts

        if not self.logger.disabled:
            self.logger.info(f"Closing {conn.src_ip}:{conn.src_port}->{conn.dst_ip}:{conn.dst_port}, {conn}")

        stats = self.window.compute(conn)
        self.logger.info(stats)
        self.window.add(conn)

    def handle_tcp(self, pkt_ip: ipv4.ipv4, pkt_tcp: tcp.tcp, ts: float):
        ts_ns = int(ts * 1e9)

        src_ip = pkt_ip.src
        dst_ip = pkt_ip.dst

        src_port = pkt_tcp.src_port
        dst_port = pkt_tcp.dst_port

        is_syn = pkt_tcp.has_flags(tcp.TCP_SYN)
        is_ack = pkt_tcp.has_flags(tcp.TCP_ACK)
        is_fin = pkt_tcp.has_flags(tcp.TCP_FIN)
        is_rst = pkt_tcp.has_flags(tcp.TCP_RST)
        is_urg = pkt_tcp.has_flags(tcp.TCP_URG)

        size = get_data_size(pkt_ip, pkt_tcp)

        if not self.logger.disabled:
            self.logger.info(
                f"Packet in {(src_ip, src_port)}->{(dst_ip, dst_port)} syn: {is_syn}, "
                f"ack: {is_ack}, fin: {is_fin}, rst: {is_rst}")

        if not self.has_conn(pkt_ip, pkt_tcp):
            conn = TcpConn(src_ip=src_ip, src_port=src_port, dst_ip=dst_ip, dst_port=dst_port,
                           start_ns=ts_ns, end_ns=0, protocol=Protocol.tcp, service=dst_port,
                           state=TcpConnState.s_init_syn, src_bytes=size, urgent=int(is_urg), land=Land.other)

            if is_syn and not is_ack and not is_rst and not is_fin:
                if src_ip == dst_ip or src_port == dst_port:
                    conn.land = Land.same_host_port

                self.set_conn(pkt_ip, pkt_tcp, conn)
            else:
                conn.wrong_fragment += 1
                conn.flag = Flag.error
                self.handle_close(conn, ts_ns)

            return

        conn = self.get_conn(pkt_ip, pkt_tcp)

        is_src = conn.src_ip == src_ip and conn.src_port == src_port

        if is_src:
            conn.src_bytes += size
        else:
            conn.dst_bytes += size

        conn.urgent += int(is_urg)

        wrong = 0
        close = False

        if is_rst:
            conn.wrong_fragment += 1
            conn.flag = Flag.error
            self.handle_state(conn, TcpConnState.rst)
            close = True
        elif conn.state == TcpConnState.s_init_syn:
            if is_syn and is_ack:
                self.handle_state(conn, TcpConnState.r_init_syn_ack)
            else:
                wrong = 1
        elif conn.state == TcpConnState.r_init_syn_ack:
            if is_ack and not is_syn:
                self.handle_state(conn, TcpConnState.s_init_ack)
            else:
                wrong = 1
        elif conn.state == TcpConnState.s_init_ack:
            if is_fin:
                if is_src:
                    self.handle_state(conn, TcpConnState.s_end_fin)
                else:
                    self.handle_state(conn, TcpConnState.r_end_fin)
            elif is_ack:
                pass
            else:
                wrong = 1
        elif conn.state == TcpConnState.s_end_fin:
            if is_ack:
                if is_fin:
                    self.handle_state(conn, TcpConnState.r_end_fin)
                else:
                    self.handle_state(conn, TcpConnState.r_end_ack)
                    close = True
            else:
                wrong = 1
        elif conn.state == TcpConnState.r_end_ack:
            if is_fin:
                self.handle_state(conn, TcpConnState.r_end_fin)
            else:
                wrong = 1
        elif conn.state == TcpConnState.r_end_fin:
            if is_ack:
                self.handle_state(conn, TcpConnState.s_end_ack)
                close = True
            else:
                wrong = 1

        if wrong > 0:
            conn.flag = Flag.error

        conn.wrong_fragment += wrong
        conn.urgent += int(is_urg)

        if close:
            self.handle_close(conn, ts_ns)
        else:
            self.set_conn(pkt_ip, pkt_tcp, conn)
