import scapy.all as scapy


def scan(ip):
    # Creating an ARP request to ask who has the specific IP we asked for
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


scan_result = scan("10.0.2.1/24")
print_result(scan_result)