from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon
from sympy import symbols, solve
import matplotlib.pyplot as plt


mac_list = ['00:a6:ca:10:1a:a0', '84:3d:c6:c8:dd:b0', '00:a6:ca:17:db:50']
pos = {'00:a6:ca:10:1a:a0': (0, 0), '84:3d:c6:c8:dd:b0': (50, -23), '00:a6:ca:17:db:50': (-40, 30)}
dist = {'00:a6:ca:10:1a:a0': 0, '84:3d:c6:c8:dd:b0': 0, '00:a6:ca:17:db:50': 0}
# x1, y1 = -1.0, -1.0
# x2, y2 = 20.0, 3.0
# x3, y3 = 3.0, 2.0
access_points = set()
res = {}
iface = "wlp3s0"
iface_mon = "wlp3s0mon"


def rssi_to_dist(rssi: int, base_rssi: int, env_factor: float) -> float:
    aux = rssi - base_rssi
    aux = (-1) * aux
    aux = float(aux) / (10 * env_factor)
    x = math.pow(10, aux)
    return x


def trilateration(macs: list, position: dict) -> [float]:
    d = {}
    for mac in macs:
        dist[mac] = rssi_to_dist(res[mac], -45, 2.3)
        d[mac] = (position[mac][0] ** 2) + (position[mac][1] ** 2) - (dist[mac] ** 2)
    x, y = symbols('x,y', real=True)
    system = [(2 * x * (position[macs[1]][0] - position[macs[0]][0])) +
              (2 * y * (position[macs[1]][1] - position[macs[0]][1])) + d[macs[0]] - d[macs[1]],
              (2 * x * (position[macs[2]][0] - position[macs[0]][0])) +
              (2 * y * (position[macs[2]][1] - position[macs[0]][1])) + d[macs[0]] - d[macs[2]]]

    q = solve(system, x, y)
    x = q[x]
    y = q[y]
    return x, y


def recv_ap_beacon(pkt) -> bool:
    global access_points

    # Check if the packet is a beacon frame from one of the access points we are interested in
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr2 in mac_list:
        # Add the MAC address of the access point to our set
        mac_address = pkt[Dot11].addr2
        rssi = pkt.dBm_AntSignal

        access_points.add(mac_address)
        res[mac_address] = rssi
        # Stop sniffing if we have seen a packet from each of the three access points
        if len(access_points) == 3:
            return True


def plot_output(macs: list, position: dict, distance: dict, x: float, y: float) -> None:
    plt.axis([-500, 500, -500, 500])
    plt.xlabel("X axis")
    plt.ylabel("Y axis")
    for mac in macs:
        plt.plot(position[mac][0], position[mac][1], "ro")
        # plt.annotate(mac + '\n' + str(round(distance[mac]) + 'meters', xy=(position[mac][0], position[mac][1]),
        #              xycoords='data', textcoords='offset points', fontsize=10,
        #              arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2")))
        plt.annotate(mac + '\n' + str(round(distance[mac])) + 'meters', xy=(pos[mac][0], pos[mac][1]),
                     xycoords='data', fontsize=10,
                     arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"))
    plt.plot(x, y, 'bo')
    plt.annotate(r'Device' + '\n' + '[' + str(round(x, 2)) + ',' + str(round(y, 2)) + ']', xy=(x, y), xycoords='data',
                 xytext=(+0, -30), textcoords='offset points', fontsize=10,
                 arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"))
    plt.show()


if __name__ == "__main__":
    os.system(f"sudo -S airmon-ng start {iface}")
    os.system("sudo tmux new -d")
    os.system(f"tmux send -Rt 0 airodump-ng SPACE {iface_mon} Enter")
    a = sniff(iface=iface_mon, prn=recv_ap_beacon, stop_filter=recv_ap_beacon)
    dev_x, dev_y = trilateration(mac_list, pos)
    print(dev_x, dev_y)
    plot_output(mac_list, pos, dist, dev_x, dev_y)
    # t = AsyncSniffer(iface=iface_mon, prn=handle_packet)
    # t.start()
    # if len(access_points) == 3:
    #     t.stop()
    # print(mac_set)
    # print(access_points)
    # print(res)
    os.system(f"sudo -S airmon-ng stop {iface_mon}")
