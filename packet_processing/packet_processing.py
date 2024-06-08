import pyshark
import logging
from server_communication.server_communication import ServerCall, Packet
from suspicious_activity.suspiciousActivity import check_sus_activity,check_unsual_port,check_unsual_traffic,check_protocol_violation,check_failed_connections_R
from utils.utils import check_private_ip

class IDS:
    def __init__(self, server_url: str, interface: str, log_file: str):
        self.server = ServerCall(server_url)
        self.interface = interface
        self.capture = pyshark.LiveCapture(interface=self.interface)
        self.ip_packet_count={}
        self.failed_connections={}
        logging.basicConfig(filename=log_file, level=logging.INFO, 
                            format='%(asctime)s - %(levelname)s - %(message)s') 
    
    def update_packet_count(self,ip:str):
        if ip in self.ip_packet_count:
            self.ip_packet_count[ip]+=1
        else:
            self.ip_packet_count[ip]=1
    def update_failed_attempts(self,ip:str):
        if ip in self.failed_connections:
            self.failed_connections[ip]+=1
        else:
            self.failed_connections[ip]=1
    
    def check_activity(self,packet: Packet):
        if check_sus_activity(packet.ipsrc) or check_sus_activity(packet.ipdst):
            logging.info(f"Found suspicious activity: {packet.ipsrc} -> {packet.ipdst}")
            return True
        if check_unsual_port(packet.srcport) or check_unsual_port(packet.dstport):
            logging.info(f"Found unusual port: {packet.srcport} -> {packet.dstport}")
            return True
        if check_unsual_traffic(packet.ipsrc,self.ip_packet_count.get(packet.ipsrc,0)) or check_unsual_traffic(packet.ipdst,self.ip_packet_count.get(packet.ipdst,0)):
            logging.info(f"Found unusual traffic: {packet.ipsrc} -> {packet.ipdst}")
            return True
        if check_protocol_violation(packet):
            logging.info(f"Found protocol violation: {packet.ipsrc} -> {packet.ipdst}")
            return True
        if check_failed_connections_R(packet,self.failed_connections.get(packet.ipsrc,0)) or check_failed_connections_R(packet,self.failed_connections.get(packet.ipdst,0)):
            logging.info(f"Found failed connection: {packet.ipsrc} -> {packet.ipdst}")
            return True
        return False

    def packet_filter(self, packet: pyshark.packet.packet.Packet):
        _dg = Packet()
        if hasattr(packet, 'ip'):
            _dg.ipsrc = packet.ip.src
            _dg.ipdst = packet.ip.dst
            _dg.time_stamp = packet.sniff_timestamp
            _dg.highest_layer = packet.highest_layer
            _dg.transport_layer = packet.transport_layer

            if packet.transport_layer in ["TCP", "UDP"]:
                if hasattr(packet, 'udp'):
                    _dg.dstport = int(packet.udp.dstport)
                    _dg.srcport = int(packet.udp.srcport)
                elif hasattr(packet, 'tcp'):
                    _dg.dstport = int(packet.tcp.dstport)
                    _dg.srcport = int(packet.tcp.srcport)

                if check_private_ip(packet.ip.src) and check_private_ip(packet.ip.dst):
                    self.update_packet_count(packet.ip.src)
                    self.update_packet_count(packet.ip.dst)
                    if self.check_activity(_dg):
                        logging.warning(f"Suspicious activity detected: {_dg.__dict__}")
                        self.server.report_message(_dg)
                    else:
                        self.server.report_message(_dg)

    def start_capture(self):
        logging.info("Starting packet capture...")
        try:
            for packet in self.capture.sniff_continuously():
                self.packet_filter(packet)
        except Exception as e:
            logging.error(f"Error during packet capture: {e}")
