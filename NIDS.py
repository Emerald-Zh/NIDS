from scapy.arch.windows import get_windows_if_list
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import logging
import re
import ipaddress

alertprotocols = []
alertdestips = []
alertsrcips = []
alertsrcports = []
alertdestports = []
alertmsgs = []


def read_rules(rulefile):
    ruleslist = []
    try:
        with open(rulefile, "r") as rf:
            for line in rf.readlines():
                if line.startswith("alert"):
                    ruleslist.append(line.strip())
    except FileNotFoundError:
        logging.error("Error: Input file not found")
    return ruleslist


def process_rules(rulelist):
    global alertprotocols, alertdestips, alertsrcips, alertsrcports, alertdestports, alertmsgs

    for rule in rulelist:
        rulewords = rule.split()
        alertprotocols.append(rulewords[1].lower() if rulewords[1] != "any" else "any")
        alertsrcips.append(rulewords[2].lower() if rulewords[2] != "any" else "any")
        alertsrcports.append(int(rulewords[3]) if rulewords[3] != "any" else "any")
        alertdestips.append(rulewords[5].lower() if rulewords[5] != "any" else "any")
        alertdestports.append(rulewords[6].lower() if rulewords[6] != "any" else "any")
        alertmsgs.append(" ".join(rulewords[7:]))


interfaces = get_windows_if_list()


def capture_packets(interfaces):
    """
    Capture packets on the specified interface.
    """
    scapy.sniff(prn=packet_callback, iface=interfaces)


def check_rules_warning(pkt, alertprotocols, alertdestips, alertsrcips, alertsrcports, alertdestports, alertmsgs):
    if pkt.haslayer('IP'):
        try:
            src = pkt['IP'].src
            dest = pkt['IP'].dst
            proto = pkt['IP'].proto
            sport = pkt['IP'].sport if 'sport' in pkt['IP'] else None
            dport = pkt['IP'].dport if 'dport' in pkt['IP'] else None

            for i in range(len(alertprotocols)):
                if alertprotocols[i] != "any":
                    chkproto = alertprotocols[i]
                else:
                    chkproto = proto

                if alertdestips[i] != "any":
                    chkdestip = alertdestips[i]
                else:
                    chkdestip = dest

                if alertsrcips[i] != "any":
                    chksrcip = alertsrcips[i]
                else:
                    chksrcip = src

                if alertsrcports[i] != "any":
                    chksrcport = alertsrcports[i]
                else:
                    chksrcport = sport

                if alertdestports[i] != "any":
                    chkdestport = alertdestports[i]
                else:
                    chkdestport = dport

                if (
                        ("/" not in chksrcip and "/" not in chkdestip and src == chksrcip and dest == chkdestip) or
                        ("/" in chksrcip and "/" in chkdestip and ipaddress.IPv4Address(src) in ipaddress.IPv4Network(
                            chksrcip) and ipaddress.IPv4Address(dest) in ipaddress.IPv4Network(chkdestip)) or
                        ("/" in chksrcip and "/" not in chkdestip and ipaddress.IPv4Address(
                            src) in ipaddress.IPv4Network(chksrcip) and dest == chkdestip) or
                        ("/" not in chksrcip and "/" in chkdestip and src == chksrcip and ipaddress.IPv4Address(
                            dest) in ipaddress.IPv4Network(chkdestip))
                ):
                    return True

        except Exception as e:
            logging.error("Error processing packet: %s" % e)
    return False


def packet_callback(pkt):
    if check_rules_warning(pkt, alertprotocols, alertdestips, alertsrcips, alertsrcports, alertdestports, alertmsgs):
        if pkt.haslayer(scapy.DNS):
            dns_layer = pkt.getlayer(scapy.DNS)
            if dns_layer.qd:
                domain_name = dns_layer.qd.qname.decode()
                logging.info("Packet matched a rule: %s - Destination URL: %s", pkt.summary(), domain_name)
        elif pkt.haslayer(scapy.IP):
            logging.info("Packet matched a rule: %s - Destination IP: %s", pkt.summary(), pkt['IP'].dst)
        elif pkt.haslayer(HTTPRequest):
            url = pkt[HTTPRequest].Host.decode() + pkt[HTTPRequest].Path.decode()
            logging.info("Packet matched a rule: %s - Destination URL: %s", pkt.summary(), url)
        elif pkt.haslayer(HTTPResponse):
            url = pkt[HTTPResponse].Host.decode() + pkt[HTTPResponse].Path.decode()
            logging.info("Packet matched a rule: %s - Destination URL: %s", pkt.summary(), url)
        else:
            logging.info("Packet matched a rule: %s - No destination information available", pkt.summary())


def main(input_file):
    logging.basicConfig(filename='traffic_logs.log', level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    rule_list = read_rules(input_file)
    process_rules(rule_list)
    wifi_interface = None
    for interface in interfaces:
        if interface['name'] == 'WLAN':
            wifi_interface = interface
            break

    if wifi_interface:
        print(f"Using Wi-Fi interface: {wifi_interface['description']}")
        capture_packets(wifi_interface['name'])
    else:
        print("Wi-Fi interface not found.")


if __name__ == "__main__":
    main("rules.txt")