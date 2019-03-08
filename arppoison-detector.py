#  Copyright (c) 2019. - ciphyr
#  Email: ciphyr[at]protonmail.com
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  You may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import scapy.all as scapy
from time import sleep
import random


# Future Improvements
# Arg for interface, improve attack_detected logic


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=analyze_packet)
    # filter= arg uses Berfekly Packet Filter (BPF) Syntax


def get_mac(targetIP):
    arp_request = scapy.ARP(pdst=targetIP)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast_request = broadcast / arp_request

    responses_list = scapy.srp(arp_broadcast_request, timeout=1, verbose=False)[0]
    return responses_list[0][1].hwsrc


def analyze_packet(packet):
    attack_detected = False
    try:
        if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
            true_mac = get_mac(packet[scapy.ARP].psrc)
            packet_hwsrc_mac = packet[scapy.ARP].hwsrc

            if true_mac != packet_hwsrc_mac:
                print("ARP Poisoning Attack Detected!")
                # execute killswitch
                attack_detected = True

        if attack_detected == False:
            sleep_time = random.randint(5, 15)
            print("Sleeping for " + str(sleep_time))
            sleep(sleep_time)

    except IndexError:
        print("Passing")
        pass


sniff("eth0")
