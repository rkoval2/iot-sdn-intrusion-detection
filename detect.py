import pickle

from sklearn.ensemble import RandomForestClassifier
import pandas as pd

from monitor import TcpConnWindowStats, TcpConnState, Flag

with open("rf.pickle", "rb") as f:
    rf: RandomForestClassifier = pickle.load(f)

df = pd.read_csv("data/input.csv", header=0, index_col=None)


def detect(stat: TcpConnWindowStats):
    conn = stat.conn

    duration_s = int((conn.end_ns - conn.start_ns) / 1e9)
    df["duration"] = duration_s
    df["src_bytes"] = conn.src_bytes
    df["dst_bytes"] = conn.dst_bytes
    df["land"] = conn.land
    df["wrong_fragment"] = conn.wrong_fragment
    df["urgent"] = conn.urgent
    df["count"] = stat.count
    df["serror_rate"] = stat.s_error_rate
    df["rerror_rate"] = stat.r_error_rate
    df["same_srv_rate"] = stat.same_srv_rate
    df["diff_srv_rate"] = stat.diff_srv_rate
    df["srv_count"] = stat.srv_count
    df["srv_serror_rate"] = stat.srv_s_error_rate
    df["srv_rerror_rate"] = stat.srv_r_error_rate
    df["srv_diff_host_rate"] = stat.srv_diff_host_rate

    df["protocol_type_tcp"] = True

    # Group MQTT with HTTP because dataset doesn't have any MQTT packets
    if conn.service == 80 or conn.service == 1883:
        df["service_http"] = True
    elif conn.service == 443:
        df["service_http_443"] = True
    elif conn.service == 25:
        df["service_smtp"] = True
    elif conn.service == 23:
        df["service_telnet"] = True
    elif conn.service == 22:
        df["service_ssh"] = True
    elif conn.service == 21:
        df["service_ftp"] = True
    elif conn.service == 20:
        df["service_ftp_data"] = True
    elif conn.service > 49151:
        df["private"] = True

    if conn.state == TcpConnState.rst:
        df["flag_RSTR"] = True

    if conn.flag == Flag.error:
        df["flag_REJ"] = True
    else:
        df["flag_SH"] = True

    return rf.predict(df)[0] == 1
