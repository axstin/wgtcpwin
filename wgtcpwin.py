import socket
import os
import re
import ipaddress
import ctypes
import atexit
import subprocess
import sys
import time
import argparse

arg_parser = argparse.ArgumentParser(description="WireGuard over TCP")
arg_parser.add_argument("config_path", help="the WireGuard config to use")
arg_parser.add_argument("--server", "-s", help="the tunnel server ip. if not provided, it is parsed from the provided config")
arg_parser.add_argument("--port", "-p", type=int, required=True, help="the tunnel server port")
arg_parser.add_argument("--listen-port", "-l", type=int, default=3333, help="the tcp tunnel port to listen on and wireguard client should connect to. default 3333")
arg_parser.add_argument("--wireguard-exe", help="location of wireguard.exe. by default, wgtcpwin looks for WireGuard in your PATH or at C:\\Program Files\\WireGuard\\wireguard.exe")
arg_parser.add_argument("--safe-activate", "-d", action="store_true", help="attempts to deactivate the tunnel, in case it's running, before activating it")
arg_parser.add_argument("--wstunnel-dest", "-r", help="wstunnel: where wstunnel should forward packets on the server. if not provided, the value `127.0.0.1:port` is used where `port` is parsed from the endpoint in the provided config")
arg_parser.add_argument("--wstunnel-exe", help="wstunnel: location of wstunnel.exe. by default, wgtcpwin looks for wstunnel in your PATH or the current directory")
args = arg_parser.parse_args()

def check_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() == 1
    except:
        return False

def elevate():
    is_admin = check_admin()
    print("[*] is admin: %r" % is_admin)
    if not is_admin:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        print("[*] quitting...")
        exit()

def parse_ipv4(address):
    try:
        return ipaddress.IPv4Address(address)
    except ValueError:
        return None

def parse_ipv4_endpoint(endpoint):
    match = re.match(r"([^:]+):(\d+)", endpoint)
    address = None
    port = None
    try:
        address = str(ipaddress.IPv4Address(match[1]))
        port = int(match[2])
        if port < 0 or port > 65535:
            return None
        return (address, port)
    except:
        return None  

def get_local_ipv4():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("10.255.255.255", 1)) # dummy ip
    ip = s.getsockname()[0]
    s.close()
    return ip

def find_file_in_dirs(name, dirs):
    for path in dirs:
        test_path = os.path.join(path, name)
        if os.path.exists(test_path):
            return os.path.abspath(test_path)
    return None

def find_file(name, search_dirs=[]):
    # check current directory
    if os.path.exists(name):
        return os.path.abspath(name)

    # check search_dirs
    if len(search_dirs) > 0:
        path = find_file_in_dirs(name, search_dirs)
        if path:
            return path

    # check PATH
    return find_file_in_dirs(name, os.environ["PATH"].split(os.pathsep))

def get_tunnel_name(config_path):
    return os.path.splitext(os.path.basename(config_path))[0]

class WireguardConfig:
    def __init__(self, filename=None):
        self.interface = {}
        self.peers = []

        if filename != None:
            self.load(filename)

    def parse(self, contents):
        section = None
        for line in contents.split("\n"):
            match = re.match(r"\[(\w+)\]", line)
            if match != None:
                tag = match[1]
                if tag == "Interface":
                    section = self.interface
                elif tag == "Peer":
                    section = {}
                    self.peers.append(section)
                else:
                    assert False, "invalid section '" + tag + "'"
                continue
            
            assert section != None, "tag expected"
            
            match = re.match(r"(\w+)[^=]*=\s*(.+)", line)
            if match != None:
                section[match[1]] = match[2]

    def load(self, filename):
        with open(filename, "r") as file:
            self.parse(file.read())

    def write_section(self, file, tag, section):
        file.write("[" + tag + "]\n")
        for _, key in enumerate(section):
            file.write("%s = %s\n" % (key, str(section[key])))
        file.write("\n")

    def save(self, filename):
        with open(filename, "w") as file:
            self.write_section(file, "Interface", self.interface)
            for peer in self.peers:
                self.write_section(file, "Peer", peer)


# need admin rights to start tunnel service
elevate()

# init
if not os.path.exists(args.config_path):
    print("error: config path '%s' does not exist" % args.config_path)
    exit()

server_ip = None
if args.server:
    server_ip = args.server
    if not parse_ipv4(server_ip):
        print("error: server ip '%s' is invalid" % server_ip)
        exit()

server_port = args.port

wstunnel_dest = None
if args.wstunnel_dest:
    wstunnel_dest = args.wstunnel_dest
    if not parse_ipv4_endpoint(wstunnel_dest):
        print("error: wstunnel destination '%s' is invalid" % wstunnel_dest)
        exit()

# find wireguard
wireguard_exe = args.wireguard_exe or find_file("wireguard.exe", ["C:\\Program Files\\WireGuard\\"])
print("[*] WireGuard path: " + str(wireguard_exe))
if not wireguard_exe or not os.path.exists(wireguard_exe):
    print("error: could not find wireguard.exe")
    exit()

# find wstunnel
wstunnel_exe = args.wstunnel_exe or find_file("wstunnel.exe")
print("[*] wstunnel path: " + str(wstunnel_exe))
if not wstunnel_exe or not os.path.exists(wstunnel_exe):
    print("error: could not find wstunnel.exe")
    exit()

def activate_tunnel(config_path):
    print("[*] activating WireGuard tunnel with config %s" % config_path)
    assert " " not in config_path, "config_path cannot have spaces" # wireguard bad
    os.system("\"%s\" /installtunnelservice %s" % (wireguard_exe, config_path))
    return get_tunnel_name(config_path)

def deactivate_tunnel(tunnel_name):
    print("[*] deactivating WireGuard tunnel '%s'" % tunnel_name)
    os.system("\"%s\" /uninstalltunnelservice %s" % (wireguard_exe, tunnel_name))

def start_tcp_tunnel(listen_port):
    print("[*] starting tcp tunnel on port %d..." % listen_port)
    return subprocess.Popen([wstunnel_exe, "-u", "--udpTimeoutSec", "-1", "-v", "-L", "0.0.0.0:%d:%s" % (listen_port, wstunnel_dest), "ws://%s:%d" % (server_ip, server_port)])

# parse config
print("[*] parsing config...")
config = WireguardConfig(args.config_path)
peer = config.peers[0]

#atexit.register(lambda: input())

# parse config endpoint
config_endpoint = parse_ipv4_endpoint(peer["Endpoint"])
if not config_endpoint:
    print("error: config endpoint '%s' is invalid" % peer["Endpoint"])
    exit()

# determine server ip and wstunnel destination
if server_ip:
    print("[*] server: %s:%d" % (server_ip, server_port))
else:
    server_ip = config_endpoint[0]
    print("[*] server: %s:%d (IP implied from config endpoint)" % (server_ip, server_port))

if wstunnel_dest:
    print("[*] wstunnel destination: %s" % wstunnel_dest)
else:
    wstunnel_dest = "127.0.0.1:%d" % config_endpoint[1]
    print("[*] wstunnel destination: %s (port implied from config endpoint)" % wstunnel_dest)

# generate config
print("[*] generating config...")

# find local endpoint
try:
    endpoint = "%s:%d" % (get_local_ipv4(), args.listen_port)
    print("[*] local endpoint: %s" % endpoint)
    peer["Endpoint"] = endpoint
except OSError as e:
    print("error: unable to get local interface IP. are you connected to a network?")
    exit()

# calculate allowed ips
print("[*] calculating AllowedIPs...")
n1 = ipaddress.ip_network("0.0.0.0/0")
n2 = ipaddress.ip_network(server_ip + "/32")
peer["AllowedIPs"] = ", ".join([str(i) for i in list(n1.address_exclude(n2))] + ["::/1", "8000::/1"])

# save
tunnel_name = get_tunnel_name(args.config_path)
script_path = os.path.dirname(os.path.realpath(__file__))
tmp_folder = os.path.join(script_path, "tmp/")
config_path = os.path.abspath(tmp_folder + tunnel_name + ".conf")
if not os.path.exists(tmp_folder):
    os.makedirs(tmp_folder)
print("[*] saving new config to %s" % config_path)
config.save(config_path)

print("[*] tunnel name: %s" % tunnel_name)

# make sure tunnel isn't running
if args.safe_activate:
    deactivate_tunnel(tunnel_name)
    time.sleep(1)

# start wstunnel
wstunnel = start_tcp_tunnel(args.listen_port)

# exit handler
def on_exit():
    deactivate_tunnel(tunnel_name)
    wstunnel.kill()
atexit.register(on_exit)

# start wireguard
time.sleep(2)
activate_tunnel(config_path)

print("[*] done! press enter to disconnect")
input()