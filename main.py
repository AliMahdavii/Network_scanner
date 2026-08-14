import socket
import ipaddress
import subprocess


def ping(io):
    result = subprocess.run(
        ["ping", "-n", "1", "-w", "1000", str(ip)],
        stdout=subprocess.DEVNULL
    )

    return result.returncode == 0


sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

sock.connect(("8.8.8.8", 80))

local_ip = sock.getsockname()[0]

sock.close()

network = ipaddress.ip_network(local_ip + "/24", strict=False)

print("Local IP: ", local_ip)
print("Network: ", network)
print("Netmask: ", network.netmask)
print("Broadcast: ", network.broadcast_address)

ip = "10.145.18.54"

if ping(ip):
    print("Online")
else:
    print("Offline")
