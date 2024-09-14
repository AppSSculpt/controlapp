from flask import Flask, jsonify
from scapy.all import ARP, Ether, srp
import socket

app = Flask(__name__)

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

def get_network_devices():
    local_ip = get_local_ip()
    ip_base = '.'.join(local_ip.split('.')[:-1]) + '.1/24'

    arp = ARP(pdst=ip_base)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []

    for sent, received in result:
        devices.append({
            'ip': received.psrc,
            'mac': received.hwsrc,
            'type': identify_device(received.psrc)
        })

    return devices

def identify_device(ip):
    return "TV"

@app.route('/devices', methods=['GET'])
def get_devices():
    devices = get_network_devices()
    return jsonify(devices)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
