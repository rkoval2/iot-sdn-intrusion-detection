# SDN Intrusion Detection And Mitigation

## Requirements

- All development done inside
  a [Mininet VM](http://mininet.org/download/#option-1-mininet-vm-installation-easy-recommended)
- Python 3.8
- [Mosquitto](https://mosquitto.org/) for simulating an IoT network, Mosquitto server and client libraries required
- [hping3](https://www.kali.org/tools/hping3/) for performing attacks

## Dependencies

Install all pip dependencies from `requirements.txt`:

```bash
pip install -r requirements.txt
```

## Run simulation

### Ryu SDN controller

Open a terminal and run the Ryu SDN controller:

```bash
ryu-manager ./controller.py
```

### Mininet simulation

Open a second terminal and run the Mininet simulated SDN network:

```bash
sudo ./mn.py
```

Allow a couple seconds for the network to initialize, after which you will be able to interact with the mininet cli. The
network consists of four hosts (h1=10.0.0.1, h2=10.0.0.2, h3=10.0.0.3, h4=10.0.0.4) and one switch (s1). The switch acts
as an ethernet hub. h1 is the Mosquitto broker server, h2 is a Mosquitto subscriber, h3 is a Mosquitto publisher (a
simulated IoT device). h1 and h2 log outputs to `/tmp/h1.out` and `/tmp/h2.out`.

To perform an attack, run `hping3` on h4 inside the mininet cli:

```bash
h4 hping3 h1 -c 20 --fast -d 120 -S -p 1883
```

This will send 20 TCP SYN packets with 120 bytes of data to h1 from h4, on port 1883 (default Mosquitto port). Observe
how the SDN controller in the other terminal detects the attack and mitigates it by blocking h4.

To verify that operation of normal IoT device was not impacted, view the h2's log file at `/tmp/h2.out` to see that
messages are still being transmitted between h3 and h2.

## Files

- [data/kddcup.data_10_percent.csv](data/kddcup.data_10_percent.csv): Dataset for training model
- [data/headers](data/headers): Headers for dataset
- [controller.py](controller.py): Ryu SDN controller application
- [detect.py](detect.py): Method to detect an attack from TCP statistics
- [main.ipynb](main.ipynb): Jupyter notebook for testing models
- [mn.py](mn.py): Mininet simulated SDN network
- [monitor.py](monitor.py): Code related to monitoring TCP connections and aggregating statistics in a 2-second window
- [mosquitto.conf](mosquitto.conf): Config file for the mosquitto server, allows all unauthenticated clients
- [preprocessing.py](preprocessing.py): Code to preprocess dataset
- [rf.pickle](rf.pickle): Trained Scikit-learn Random Forest classifier model

## Troubleshooting

If the mininet process doesn't exit cleanly run `sudo mn -c` to clear mininet processes and files
