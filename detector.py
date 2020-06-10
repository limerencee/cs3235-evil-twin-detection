# Acknowledgements:
# https://github.com/anotherik/RogueAP-Detector
# https://www.shellvoide.com/python/how-to-code-a-simple-wireless-sniffer-in-python/

import threading, os, time, random
from scapy.all import *

known_networks = {}
violation_counts = {}
deauth_list = {}

# Auxiliary function to format printed lines.
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Auxiliary function that will periodically change the channel it is listening
# on.
def hopper(iface):
    n = 1
    stop_hopper = False
    while not stop_hopper:
        time.sleep(0.50)
        os.system('iwconfig %s channel %d' % (iface, n))
        dig = int(random.random() * 14)
        if dig != 0 and dig != n:
            n = dig

# Prints a formatted output for detected deauth packets.
def print_deauth_status(pair):
    line = 0
    v1, v2 = eval(pair)
    print (bcolors.WARNING + "\n\t[#] Deauthentication Packet : {} <---> {} "
    + "\n\t[#]\t       Packet Count : {}"
    + bcolors.ENDC).format(v1, v2, deauth_list[pair])
    line += 3

    # Backspace trick
    sys.stdout.write("\033[{}A".format(line))

# Prints a formatted output for detected evil twin AP.
def print_eviltwin_status(pktEssid, pktBssid):
    line = 0
    print (bcolors.FAIL + "\n\n\n\n\t[!] Highly probably EvilTwin AP found!"
    + "\n\t\t\t      ESSID : [{}]\n\t\t\t      BSSID : [{}]".format(pktEssid,
    pktBssid) + bcolors.ENDC)
    line += 7

    # Backspace trick
    sys.stdout.write("\033[{}A".format(line))

# Checks if the deauthentication packet has already been tracked and increment
# its counter in deauth_list. If this counter exceeds 100, a deauthentication
# attack is going on.
def parseDeauthPacket(pkt):
    victim1 = pkt.addr2
    victim2 = pkt.addr1
    pair = str([victim1, victim2])
    if pair in deauth_list.keys():
        deauth_list[pair] += 1
        if deauth_list[pair] > 100:
            print_deauth_status(pair)
    else:
        deauth_list[pair] = 1

# Checks if the beacon frame ESSID and BSSID pair has already been tracked. If
# the ESSID already exists and the BSSID does not match the saved record,
# increment the counter for the ESSID. If this counter exceeds 100, an evil twin
# AP is highly likely to be present.
def parseEvilTwin(pkt):
    pktBssid = pkt.getlayer(Dot11).addr2
    pktEssid = pkt.getlayer(Dot11Elt).info

    # Duplicate ESSID, need to check if BSSID matches stored pair.
    if pktEssid in known_networks:
        knownBssid = known_networks[pktEssid]

        # If the BSSID do not match, increment violation_count of this ESSID
        # by 1.
        if knownBssid != pktBssid:
            if pktEssid not in violation_counts:
                violation_counts[pktEssid] = 1
            else:
                violation_counts[pktEssid] += 1

            # If the violation_count of this ESSID exceeds 100, it means that
            # this ESSID-BSSID pair is an EvilTwin as it is flooding the network
            # with its beacon frames.
            if violation_counts[pktEssid] > 100:
                print_eviltwin_status(pktEssid, pktBssid)

    else:
        known_networks[pktEssid] = pktBssid
        print (bcolors.OKGREEN + "\t[+] Added the following pair: "
        + "<{}, {}>".format(pktEssid, pktBssid) + bcolors.ENDC)

# Parses packets captured by the NIC. EvilTwn detection is currently based on
# the following 2 heuristics:
#
# 1) If there is an deauthentication attack going on, it is likely that an
#    evil twin is present.
# 2) If there is a duplicated AP with matching ESSID but varying BSSID and is
#    flooding the network with its beacon frames, it is likely that this AP is
#    an evil twin.
def parsePacket(pkt):

    # If deauth frame is detected
    if pkt.haslayer(Dot11Deauth):
        parseDeauthPacket(pkt)

    # If beacon frame is detected
    elif pkt.haslayer(Dot11Beacon):
        parseEvilTwin(pkt)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: {} iface".format(sys.argv[0])
        sys.exit(0)

    # Print group banner
    print (bcolors.HEADER + "\t\t\t===================================="
    + bcolors.ENDC)
    print (bcolors.HEADER + "\t\t\t||" + bcolors.FAIL + "      EvilTwin AP"
    + " Detector      " + bcolors.HEADER + "||" + bcolors.ENDC)
    print (bcolors.HEADER + "\t\t\t||" + bcolors.OKBLUE + "    Done by:  CS3235"
    + " Group 5    " + bcolors.HEADER + "||" + bcolors.ENDC)
    print (bcolors.HEADER + "\t\t\t||" + bcolors.OKBLUE + "     Semester: AY192"
    + "0 Sem 1     " + bcolors.HEADER + "||" + bcolors.ENDC)
    print (bcolors.HEADER + "\t\t\t===================================="
    + bcolors.ENDC)

    # Ready the interface
    interface = sys.argv[1]
    print (bcolors.WARNING + "\n\t[i] Attempting to switch {} to monitor mode"
    + "..." + bcolors.ENDC).format(interface)
    os.system("ifconfig {} down".format(interface))
    os.system("iwconfig {} mode monitor".format(interface))
    os.system("ifconfig {} up".format(interface))
    print (bcolors.OKGREEN + "\t[+] {} switched to monitor mode successfully!"
    + "\n" + bcolors.ENDC).format(interface)

    # Ready the channel hopper
    print (bcolors.WARNING + "\t[i] Starting channel hopper thread..."
    + bcolors.ENDC)
    thread = threading.Thread(target=hopper, args=(interface, ), name="hopper")
    thread.daemon = True
    thread.start()
    print (bcolors.OKGREEN + "\t[+] Hopper thread started successfully!\n"
    + bcolors.ENDC)

    print bcolors.WARNING + "\t[i] Sniffing nearby frames ...\n" + bcolors.ENDC
    sniff(iface=interface, prn=parsePacket)
