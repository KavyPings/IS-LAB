# LAB 8 - ADDITIONAL QUESTION 2
# "Configure and use Snort as a NIDS to monitor real-time network traffic.
#  Capture traffic, apply Snort rules, analyse the logs to identify intrusions."
#
# Snort is a separate program that needs root and a real network interface,
# so it cannot run inside a Python virtual environment in an exam. This file
# therefore does two things:
#
#   PART A  the real snort / tcpdump commands and a real snort.rules file,
#           as comments - put these in the write-up
#   PART B  a small Snort-style rule engine in Python that parses rules in
#           Snort syntax, runs them over a captured traffic log and produces
#           the alert output, so there is something to RUN and show
#
# ------------------------------------------------------------------------
# PART A : the real commands (write these in the answer sheet)
# ------------------------------------------------------------------------
#   sudo apt install snort
#   snort -V                                      version / confirm install
#   ip addr                                       find the interface name
#
#   # capture first, analyse later (safer in a lab)
#   sudo tcpdump -i eth0 -w capture.pcap
#
#   # sniffer mode: just print packets
#   sudo snort -v -i eth0
#   # packet logger mode: write to a directory
#   sudo snort -dev -l /var/log/snort -i eth0
#   # NIDS mode: apply the rule file
#   sudo snort -A console -q -c /etc/snort/snort.conf -i eth0
#   # replay a capture through the rules, no root needed
#   snort -A console -q -c /etc/snort/snort.conf -r capture.pcap
#
#   # the alert log
#   sudo tail -f /var/log/snort/alert
#
#   /etc/snort/rules/local.rules :
#     alert icmp any any -> $HOME_NET any (msg:"ICMP ping detected"; sid:1000001; rev:1;)
#     alert tcp any any -> $HOME_NET 22 (msg:"SSH connection attempt"; sid:1000002; rev:1;)
#     alert tcp any any -> $HOME_NET 80 (msg:"SQL injection attempt";
#          content:"' OR 1=1"; nocase; sid:1000003; rev:1;)
#     alert tcp any any -> $HOME_NET any (msg:"Nmap SYN scan"; flags:S;
#          threshold:type threshold, track by_src, count 20, seconds 5; sid:1000004; rev:1;)
#
#   rule anatomy:
#     action protocol src_ip src_port -> dst_ip dst_port (options)
#     action   : alert / log / pass / drop
#     msg      : the text that appears in the alert
#     content  : a byte string to look for in the payload
#     flags    : TCP flags, S = SYN
#     threshold: how many times before alerting (rate based detection)
#     sid      : unique rule id, 1000000+ for local rules
# ------------------------------------------------------------------------

import re
from collections import defaultdict

# ---------- PART B : a Snort-style engine ----------

RULES_TEXT = '''
alert icmp any any -> 192.168.1.0/24 any (msg:"ICMP ping detected"; sid:1000001;)
alert tcp any any -> 192.168.1.0/24 22 (msg:"SSH connection attempt"; sid:1000002;)
alert tcp any any -> 192.168.1.0/24 80 (msg:"SQL injection attempt"; content:"' OR 1=1"; nocase; sid:1000003;)
alert tcp any any -> 192.168.1.0/24 80 (msg:"Directory traversal attempt"; content:"../../"; sid:1000004;)
alert tcp any any -> 192.168.1.0/24 any (msg:"Possible SYN scan"; flags:S; threshold:5; sid:1000005;)
alert tcp any any -> 192.168.1.0/24 23 (msg:"Telnet in use - cleartext"; sid:1000006;)
'''

# a captured traffic log: one packet per line
#   time | protocol | src_ip | src_port | dst_ip | dst_port | flags | payload
TRAFFIC = '''
10:00:01|icmp|203.0.113.9|0|192.168.1.10|0||echo-request
10:00:02|tcp|203.0.113.9|40001|192.168.1.10|22|S|SSH-2.0-OpenSSH_8.9
10:00:03|tcp|198.51.100.7|51000|192.168.1.10|80|PA|GET /index.php?id=1 HTTP/1.1
10:00:04|tcp|198.51.100.7|51001|192.168.1.10|80|PA|GET /login.php?u=admin' OR 1=1 -- HTTP/1.1
10:00:05|tcp|198.51.100.7|51002|192.168.1.10|80|PA|GET /../../etc/passwd HTTP/1.1
10:00:06|tcp|203.0.113.9|40002|192.168.1.11|21|S|
10:00:06|tcp|203.0.113.9|40003|192.168.1.11|22|S|
10:00:06|tcp|203.0.113.9|40004|192.168.1.11|23|S|
10:00:06|tcp|203.0.113.9|40005|192.168.1.11|25|S|
10:00:06|tcp|203.0.113.9|40006|192.168.1.11|80|S|
10:00:06|tcp|203.0.113.9|40007|192.168.1.11|443|S|
10:00:07|tcp|192.168.1.50|33000|192.168.1.10|23|PA|USER admin PASS admin123
10:00:08|tcp|10.0.0.5|45000|192.168.1.10|443|PA|TLS handshake
10:00:09|udp|203.0.113.9|53|192.168.1.10|53||dns query example.com
'''

RULE_PATTERN = re.compile(
    r"^(?P<action>\w+)\s+(?P<proto>\w+)\s+(?P<src>\S+)\s+(?P<sport>\S+)\s*->\s*"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s*\((?P<options>.*)\)\s*$")


def parse_rules(text):
    rules = []
    for line in text.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = RULE_PATTERN.match(line)
        if not match:
            print("  cannot parse rule:", line[:50])
            continue
        rule = match.groupdict()
        options = {}
        for part in rule["options"].split(";"):
            part = part.strip()
            if not part:
                continue
            if ":" in part:
                name, value = part.split(":", 1)
                options[name.strip()] = value.strip().strip('"')
            else:
                options[part] = True
        rule["options"] = options
        rules.append(rule)
    return rules


def parse_traffic(text):
    packets = []
    for line in text.strip().split("\n"):
        fields = line.split("|")
        if len(fields) != 8:
            continue
        packets.append({"time": fields[0], "proto": fields[1],
                        "src": fields[2], "sport": fields[3],
                        "dst": fields[4], "dport": fields[5],
                        "flags": fields[6], "payload": fields[7]})
    return packets


def in_network(ip, spec):
    if spec == "any":
        return True
    if spec.endswith("/24"):
        return ip.rsplit(".", 1)[0] == spec[:-3].rsplit(".", 1)[0]
    return ip == spec


def port_matches(port, spec):
    return spec == "any" or port == spec


def matches(rule, packet):
    if rule["proto"] != "any" and rule["proto"] != packet["proto"]:
        return False
    if not in_network(packet["src"], rule["src"]):
        return False
    if not in_network(packet["dst"], rule["dst"]):
        return False
    if not port_matches(packet["sport"], rule["sport"]):
        return False
    if not port_matches(packet["dport"], rule["dport"]):
        return False

    options = rule["options"]
    if "content" in options:
        needle = options["content"]
        haystack = packet["payload"]
        if options.get("nocase"):
            needle, haystack = needle.lower(), haystack.lower()
        if needle not in haystack:
            return False
    if "flags" in options and options["flags"] != packet["flags"]:
        return False
    return True


def run_engine(rules, packets):
    alerts = []
    counters = defaultdict(int)
    for packet in packets:
        for rule in rules:
            if not matches(rule, packet):
                continue
            threshold = int(rule["options"].get("threshold", 1))
            key = (rule["options"]["sid"], packet["src"])
            counters[key] += 1
            if counters[key] < threshold:
                continue                    # not enough hits yet
            alerts.append((packet, rule, counters[key]))
    return alerts


print("=" * 78)
print(" Snort-style NIDS : parse rules, replay a capture, report intrusions")
print("=" * 78)

rules = parse_rules(RULES_TEXT)
packets = parse_traffic(TRAFFIC)
print("loaded %d rules and %d packets" % (len(rules), len(packets)))
print()

print("--- the rule set ---")
for rule in rules:
    print("  sid %s  %-4s %-16s -> %-16s port %-4s  %s"
          % (rule["options"]["sid"], rule["proto"], rule["src"], rule["dst"],
             rule["dport"], rule["options"]["msg"]))
print()

print("--- alert output (what /var/log/snort/alert would contain) ---")
alerts = run_engine(rules, packets)
for packet, rule, count in alerts:
    print("[**] [1:%s:1] %s [**]" % (rule["options"]["sid"], rule["options"]["msg"]))
    print("     %s  %s %s:%s -> %s:%s%s"
          % (packet["time"], packet["proto"].upper(), packet["src"], packet["sport"],
             packet["dst"], packet["dport"],
             "  flags=" + packet["flags"] if packet["flags"] else ""))
    if "content" in rule["options"]:
        print("     matched content: %r" % rule["options"]["content"])
    if int(rule["options"].get("threshold", 1)) > 1:
        print("     hit %d from this source (threshold %s)"
              % (count, rule["options"]["threshold"]))
print()

print("--- log analysis ---")
by_rule = defaultdict(int)
by_source = defaultdict(int)
for packet, rule, _ in alerts:
    by_rule[rule["options"]["msg"]] += 1
    by_source[packet["src"]] += 1

print(" alerts per rule:")
for message, count in sorted(by_rule.items(), key=lambda kv: -kv[1]):
    print("   %-32s %d" % (message, count))
print(" alerts per source address:")
for ip, count in sorted(by_source.items(), key=lambda kv: -kv[1]):
    print("   %-18s %d" % (ip, count))
print()

worst = max(by_source, key=by_source.get)
print("--- conclusion for the write-up ---")
print(" %s raised the most alerts (%d)." % (worst, by_source[worst]))
print(" The pattern - SYN packets to ports 21, 22, 23, 25, 80, 443 within one")
print(" second from a single address - is a port scan, not normal traffic.")
print(" 198.51.100.7 sent an SQL injection string and a directory traversal")
print(" attempt to the web server, so that host is actively attacking the app.")
print(" Telnet on port 23 from 192.168.1.50 carried a password in cleartext;")
print(" that is a configuration fault on the inside, not an attack.")
print()
print("--- the limits of this kind of detection ---")
print(" Signature based NIDS only catches what a rule describes. It cannot see")
print(" inside TLS, it misses anything new, and noisy rules cause alert fatigue.")
print(" Anomaly based detection catches the unknown but produces false positives.")
