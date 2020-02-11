import scapy.all as scapy
import argparse


def get_arguments():
    '''Allow to run script with options as -t or --target
       python network_scaner.py --target 10.0.0.0/16 or 
       python network_scaner.py -t 10.0.0.0/16'''
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="Target IP/IP Range")
    options = parser.parse_args()
    return options


def scan(ip):
    # Creating an ARP request to ask who has the specific IP on a local ethernet network
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()

    # Setting our destination MAC to broadcast MAC address to make sure that
    # it is sent to all the clients on the same network
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()

    # This variable is your packet that will be sent across the network,
    # as it contains information about MAc and ARP
    arp_request_broadcast = broadcast/arp_request # combination of both variables we created
    # arp_request_broadcast.show()

    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    # srp stands for send and receive packet.

    client_list = []
    for e in answered_list:
        client_dict = {"ip": e[1].psrc, "mac": e[1].hwsrc}
        client_list.append(client_dict)
    return client_list


# Printing the result
def print_result(result_list):
    print("IP\t\t\tMAC Address\n -----------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)