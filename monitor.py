import time
from dataclasses import dataclass
from enum import Enum
from typing import Deque
from collections import deque


def get_service(port: int) -> int:
    if port == 80:
        return Service.http
    if port == 443:
        return Service.https
    if port == 23:
        return Service.telnet
    if port == 21 or port == 20:
        return Service.ftp
    return Service.unknown


class Protocol:
    unknown = 0
    tcp = 1


class Service:
    unknown = 0
    http = 1
    https = 2
    telnet = 3
    ftp = 4


class Flag:
    unknown = 0
    normal = 1
    error = 2


class Land:
    other = 0
    same_host_port = 1


class TcpConnState(Enum):
    s_init_syn = 1
    r_init_syn_ack = 2
    s_init_ack = 3

    s_end_fin = 4
    r_end_ack = 5
    r_end_fin = 6
    s_end_ack = 7

    rst = 8


@dataclass
class TcpConn:
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int

    state: TcpConnState
    start_ns: int
    end_ns: int

    service: int = 0
    protocol: int = 0
    src_bytes: int = 0
    dst_bytes: int = 0
    flag: int = 0
    land: int = 0
    wrong_fragment: int = 0
    urgent: int = 0


@dataclass
class TcpConnWindowStats:
    conn: TcpConn

    # Same-host connections
    count: int = 0
    s_error_rate: float = 0
    r_error_rate: float = 0
    same_srv_rate: float = 0
    diff_srv_rate: float = 0

    # Same-service connections
    srv_count: int = 0
    srv_s_error_rate: float = 0
    srv_r_error_rate: float = 0
    srv_diff_host_rate: float = 0


class TcpConnWindow:
    window: Deque[TcpConn]
    index: 0

    def __init__(self):
        self.window = deque()

    def add(self, conn: TcpConn):
        self.window.append(conn)

    def stats(self):
        # Remove connections older than 2 seconds
        ts = time.time_ns() - 2_000_000_000
        while len(self.window) > 0 and self.window[0].end_ns < ts:
            self.window.popleft()

        stats = []

        if len(self.window) == 0:
            return stats

        for conn in self.window:
            stats.append(self.compute(conn))

        return stats

    def compute(self, conn: TcpConn) -> TcpConnWindowStats:
        if len(self.window) == 0:
            return TcpConnWindowStats(conn=conn)

        count = 0
        s_error = 0
        r_error = 0
        same_srv = 0
        diff_srv = 0
        srv_s_error = 0
        srv_r_error = 0
        srv_count = 0
        srv_diff_host = 0

        for window_conn in self.window:
            if window_conn == conn:
                continue

            if window_conn.dst_ip == conn.dst_ip:
                count += 1

                if window_conn.flag == Flag.error:
                    s_error += 1
                    r_error += 1

                if window_conn.service == conn.service:
                    same_srv += 1
                else:
                    diff_srv += 1

            if window_conn.service == conn.service:
                srv_count += 1

                if window_conn.flag == Flag.error:
                    srv_s_error += 1
                    srv_r_error += 1

                if window_conn.dst_ip != conn.dst_ip:
                    srv_diff_host += 1

        if count == 0 or srv_count == 0:
            return TcpConnWindowStats(conn=conn)

        return TcpConnWindowStats(conn=conn,
                                  count=count,
                                  s_error_rate=s_error / count,
                                  r_error_rate=r_error / count,
                                  same_srv_rate=same_srv / count,
                                  diff_srv_rate=diff_srv / count,
                                  srv_count=srv_count,
                                  srv_s_error_rate=srv_s_error / srv_count,
                                  srv_r_error_rate=srv_r_error / srv_count,
                                  srv_diff_host_rate=srv_diff_host / srv_count)
