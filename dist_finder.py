import os

from scapy.all import *
from scapy.layers.dot11 import Dot11

ssid = "Xiaomi 11T Pro"
iface = "wlp3s0"
iface_mon = "wlp3s0mon"
mac_set = set()


def distance(rssi, base_rssi, n=2.3):
    aux = rssi - base_rssi
    aux = (-1) * aux
    aux = float(aux) / (10 * n)
    x = math.pow(10, aux)
    return x


def base_rssi(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0:
            try:
                if pkt.info.decode() == ssid:
                    mac = pkt.addr2
                    rssi = -(256 - ord(pkt.notdecoded[-4:-3]))
                    print(f"MAC: {pkt.info.decode()}, RSSI:: {rssi}")
            except AttributeError:
                pass
                # print("pkt.info raised an error")


def distance_finder(pkt):
    if pkt.haslayer(Dot11):
        if pkt.type == 0:
            try:
                if pkt.info.decode() == ssid:
                    mac = pkt.addr2
                    mac_set.add(mac)
                    rssi = -(256 - ord(pkt.notdecoded[-4:-3]))
                    dist = distance(rssi, -50)
                    print(f"SSID: {pkt.info.decode()}, mac: {mac}, RSSI: {rssi}, Distance: {dist} meters")
            except AttributeError:
                print(AttributeError)
                # print("pkt.info raised an error")


res = {}


def find_base_rssi(pkt) -> dict:
    global res
    ap = ["Amir", "omid", "Sahar"]
    ap = "Amir"

    if pkt.haslayer(Dot11):
        if pkt.type == 0:
            try:
                if pkt.info.decode() in ap:
                    rssi = -(256 - ord(pkt.notdecoded[-4:-3]))
                    if pkt.info.decode() in res:
                        res[pkt.info.decode()].append(rssi)
                    else:
                        res[pkt.info.decode()] = [rssi]
            except AttributeError:
                pass
                # raise
                # print("pkt.info raised an error")


if __name__ == "__main__":
    os.system(f"sudo -S airmon-ng start {iface}")
    os.system("sudo tmux new -d")
    os.system(f"tmux send -Rt 0 airodump-ng SPACE {iface_mon} Enter")
    a = sniff(iface=iface_mon, prn=distance_finder, count=5000)
    os.system(f"sudo -S airmon-ng stop {iface_mon}")
    print(mac_set)
