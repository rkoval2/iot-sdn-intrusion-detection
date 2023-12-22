import pickle

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neural_network import MLPClassifier
import pandas as pd

from monitor import TcpConnWindowStats, TcpConnState, Flag


def read_model(name):
    with open(f"{name}.pickle", "rb") as f:
        return pickle.load(f)


class Detector:
    def __init__(self):
        self.rf: RandomForestClassifier = read_model("rf")
        self.lr: LogisticRegression = read_model("lr")
        self.clf: MLPClassifier = read_model("clf")

        self.models = [self.rf, self.lr, self.clf]

        self.df = pd.read_csv("data/input.csv", header=0, index_col=None)

    def get_input(self):
        return self.df.copy(deep=True)

    def detect(self, stat: TcpConnWindowStats):
        conn = stat.conn

        duration_s = int((conn.end_ns - conn.start_ns) / 1e9)

        df = self.get_input()

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

        positives = 0
        for model in self.models:
            if model.predict(df)[0] > 0:
                positives += 1

        return positives > 1
