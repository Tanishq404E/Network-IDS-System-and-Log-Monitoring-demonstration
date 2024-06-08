import base64
import json
import pyshark
import netifaces
import ipaddress

import requests

class packt(object):
    def __init__(self,time_stamp:str='',ipsrc:str='',ipdst:str='',srcport:int=0,dstport:int=0,transport_layer:str='',highest_layer:str=''):
        self.time_stamp=time_stamp
        self.ipsrc= ipsrc
        self.ipdst= ipdst
        self.srcport= srcport
        self.dstport= dstport
        self.transport_layer= transport_layer
        self.highest_layer= highest_layer
        

class serverCall(object):
    def __init__(self,ip:str,port:int):
        self.ip= ip
        self.port= port
        pass
server=serverCall('192.168.2.132','8080')


#print(netifaces.gateways()['default'][netifaces.AF_INET][1])
use_gateway = "\\Device\\NPF_{06D40270-E76A-48A5-B255-A0D8BDBE4948}"
use_gateway="\\Device\\NPF_"+str(netifaces.gateways()['default'][netifaces.AF_INET][1])
Capture=pyshark.LiveCapture(interface=use_gateway)

def is_api_server(packet:Capture,server:serverCall):
    '''
    Check if packet is communicating with the reporting server aka canary for now
    Args:
        packet: generated from Capture
        server: serverCall object
    Returns:
        bool: True if packet is communicating with server, False if not
    '''
    if ((hasattr(packet,'ip')) and (hasattr(packet,'tcp'))):
        if ((packet.ip.src==server.ip) or (packet.ip.dst==server.ip)):
            return True
        else:
            return False
server=serverCall('192.168.2.132','8080')

def check_privateIP(ip_addr:str):
    '''
    We are checking for private IP address RFC1918
    Args:
        ip_addr: IP address to check
    Returns:
        True if private IP address, False if not
    '''
    iP = ipaddress.ip_address(ip_addr)
    return iP.is_private

def reportMessage(message:packt):
    bottle=json.dumps(message.__dict__)
    
    jsonString=bottle.encode('ascii')
    b64=base64.b64encode(jsonString)
    jsonPayload=b64.decode('utf8').replace("'",'"')
    print(jsonPayload)
    
    try:
        test=requests.post('http://' + server.ip + ':' + server.port + '/report',json=jsonPayload)
    except requests.exceptions.RequestException as e:
        # do logging to local file
        print(e)

def cap_filters(packet:Capture): 
    '''
    Filter out packets on given conditions
    Args:
        packet: generated from Capture
    '''
    #check communcation to canary
    if is_api_server(packet,server) is True:
        
        return
    if hasattr(packet,"icmp"):
        _dg=packt()
        _dg.ipdst=packet.ip.dst
        _dg.ipsrc=packet.ip.src
        _dg.highest_layer=packet.highest_layer
        _dg.time_stamp=packet.sniff_timestamp
        reportMessage(_dg)
        
    if packet.transport_layer=="TCP" or packet.transport_layer=="UDP":
        _dg=packt()
        if hasattr(packet,'ipv6'):
            
            #Returns none when ipv6 packet is found
            
            return None
        
        if hasattr(packet,'ip'):
            if (check_privateIP(packet.ip.src) is True) and (check_privateIP(packet.ip.dst) is True):
                _dg.ipsrc=packet.ip.src
                _dg.ipdst=packet.ip.dst
                _dg.time_stamp=packet.sniff_timestamp
                _dg.highest_layer=packet.highest_layer
                _dg.transport_layer=packet.transport_layer
                if hasattr(packet,'UDP'):
                    _dg.dstport=packet.UDP.dstport
                    _dg.srcport=packet.UDP.srcport
                if hasattr(packet,'tcp'):
                    _dg.dstport=packet.tcp.dstport
                    _dg.srcport=packet.tcp.srcport
                reportMessage(_dg)
                pass
                
        pass
    
    
    

for packet in Capture.sniff_continuously():
    cap_filters(packet)