# TODO: instead of the first ping, consider a list of RSSI values, Detect anomalies and then calculate the mean.
import numpy as np
from scapy.all import *
from scapy.layers.dot11 import Dot11, Dot11Beacon
from sympy import symbols, solve
import matplotlib.pyplot as plt
# import matplotlib.animation as animation
import time
import os

# os.environ['GDK_CORE_DEVICE_EVENTS'] = '1'  # Supress the Gdk message
# Amir - Xiaomi 11T Pro - HONOR 70

mac_list = ['72:0c:54:ed:d8:19', '46:6b:cd:d4:ae:90', '86:00:91:84:c6:df']
pos = {'72:0c:54:ed:d8:19': (0, 0), '46:6b:cd:d4:ae:90': (2, 1), '86:00:91:84:c6:df': (3, 0)}
dist = {'72:0c:54:ed:d8:19': 0, '46:6b:cd:d4:ae:90': 0, '86:00:91:84:c6:df': 0}
# x1, y1 = -1.0, -1.0
# x2, y2 = 20.0, 3.0
# x3, y3 = 3.0, 2.0
# access_points = set()
access_points = {'72:0c:54:ed:d8:19': [], '46:6b:cd:d4:ae:90': [], '86:00:91:84:c6:df': []}
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
        dist[mac] = rssi_to_dist(res[mac], -55, 2.7)
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


def reject_outliers(data, m=2.):
    data = np.array(data)
    d = np.abs(data - np.median(data))
    mdev = np.median(d)
    s = d / (mdev if mdev else 1.)
    return data[s < m]


# def recv_ap_beacon(pkt) -> bool:
#     global access_points
#
#     # Check if the packet is a beacon frame from one of the access points we are interested in
#     if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr2 in mac_list:
#         # Add the MAC address of the access point to our set
#         mac_address = pkt[Dot11].addr2
#         rssi = pkt.dBm_AntSignal
#
#         access_points.add(mac_address)
#         res[mac_address] = rssi
#         # Stop sniffing if we have seen a packet from each of the three access points
#         if len(access_points) == 3:
#             return True


def recv_ap_beacon(pkt) -> bool:
    global access_points, mac_list
    # if len(access_points[mac_list[0]]) == 5 & len(access_points[mac_list[1]]) == 5 & \
    #         len(access_points[mac_list[2]]) == 5:
    #     access_points[mac_list[0]] = []
    #     access_points[mac_list[1]] = []
    #     access_points[mac_list[2]] = []
    # Check if the packet is a beacon frame from one of the access points we are interested in
    if pkt.haslayer(Dot11Beacon) and pkt[Dot11].addr2 in mac_list:
        # Add the MAC address of the access point to our set
        mac_address = pkt[Dot11].addr2
        rssi = pkt.dBm_AntSignal
        if mac_address in mac_list:
            if len(access_points[mac_address]) < 5:
                access_points[mac_address].append(rssi)
        # Stop sniffing if we have seen a packet from each of the three access points
        if len(access_points[mac_list[0]]) == 5 & len(access_points[mac_list[1]]) == 5 & \
                len(access_points[mac_list[2]]) == 5:
            ap0 = np.mean(access_points[mac_list[0]])  # use reject_outliers()
            ap1 = np.mean(access_points[mac_list[1]])
            ap2 = np.mean(access_points[mac_list[2]])
            res[mac_list[0]] = ap0
            res[mac_list[1]] = ap1
            res[mac_list[2]] = ap2
            return True


def plot_output(macs: list, position: dict, distance: dict, x: float, y: float) -> None:
    plt.axis([-10, 10, -10, 10])
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

#
# #######################################################################  ANIMATION
# Create a figure and an axis object for the plot
# fig, ax = plt.subplots()
# def update_plot(macs: list, position: dict, distance: dict, x: float, y: float) -> None:
#     # Clear the current axis
#     ax.clear()
#     ax.axis([-100, 100, -100, 100])
#     ax.set_xlabel("X axis")
#     ax.set_ylabel("Y axis")
#
#     # Plot the access points
#     for mac in macs:
#         ax.plot(position[mac][0], position[mac][1], "ro")
#         ax.annotate(mac + '\n' + str(round(distance[mac])) + 'meters', xy=(position[mac][0], position[mac][1]),
#                     xycoords='data', fontsize=10,
#                     arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"))
#
#     # Plot the device location
#     ax.plot(x, y, 'bo')
#     ax.annotate(r'Device' + '\n' + '[' + str(round(x, 2)) + ',' + str(round(y, 2)) + ']', xy=(x, y), xycoords='data',
#                 xytext=(+0, -30), textcoords='offset points', fontsize=10,
#                 arrowprops=dict(arrowstyle="->", connectionstyle="arc3,rad=.2"))
#
#
# # Define the animation function
# def animate(i):
#     global pos
#     a = sniff(iface=iface_mon, prn=recv_ap_beacon, stop_filter=recv_ap_beacon)
#     # Call the trilateration function to get the updated device location
#     dev_x, dev_y = trilateration(mac_list, pos)
#     # Call update_plot to update the plot with the new device location
#     update_plot(mac_list, pos, dist, dev_x, dev_y)
# #######################################################################  ANIMATION END


if __name__ == "__main__":
    os.system(f"sudo -S airmon-ng start {iface}")
    os.system("sudo tmux new -d")
    os.system(f"tmux send -Rt 0 airodump-ng SPACE {iface_mon} Enter")
    a = sniff(iface=iface_mon, prn=recv_ap_beacon, stop_filter=recv_ap_beacon)
    # ani = animation.FuncAnimation(fig, animate, interval=1000)
    print(access_points)
    dev_x, dev_y = trilateration(mac_list, pos)
    print(dev_x, dev_y)
    plot_output(mac_list, pos, dist, dev_x, dev_y)
    # OR:
    # i = 0
    # while i < 5:
    #     a = sniff(iface=iface_mon, prn=recv_ap_beacon, stop_filter=recv_ap_beacon)
    #     dev_x, dev_y = trilateration(mac_list, pos)
    #     print(dev_x, dev_y)
    #     access_points[mac_list[0]] = []
    #     access_points[mac_list[1]] = []
    #     access_points[mac_list[2]] = []
    #     i += 1
    # t = AsyncSniffer(iface=iface_mon, prn=handle_packet)
    # t.start()
    # if len(access_points) == 3:
    #     t.stop()
    os.system(f"sudo airmon-ng stop {iface_mon}")
