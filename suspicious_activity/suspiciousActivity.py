import ipaddress

'''
    For testing purposes, we will use the following list of IP addresses as the list of suspicious IP addresses
    For futher implementation we can create a function to import a list from .csv file
'''
suspectIP = ['0.0.0.0','172.25.180.61']

def check_sus_activity(ip)-> bool:
    return ip in suspectIP

def check_unsual_port(port:int) -> bool:
    '''
        This function will check if the port is a common port
        For further implementation we can import the port number from the given .csv file
    '''
    commonPort={80, 443, 22, 21, 25, 110, 143, 53, 123, 587, 993, 995, 465, 8080}
    return port not in commonPort

def check_unsual_traffic(ip:str,packet_c:int,threshold:int=100) -> bool:
    '''
        It checks whether the frequency crosses the threshold frequency or not and also checks if the IP is in the suspicious IP list.
    '''
    return packet_c > threshold and check_sus_activity(ip)

def check_protocol_violation(packet) -> bool:
    if packet.highest_layer == "HTTP" and packet.transport_layer == "TCP":
        return packet.srcport not in [80, 443] and packet.dstport not in [80, 443]
    return False
def check_failed_connections_R(packet,failed_connection:int,threshold:int=10) -> bool:
    return failed_connection > threshold and check_sus_activity(packet.ipsrc)


