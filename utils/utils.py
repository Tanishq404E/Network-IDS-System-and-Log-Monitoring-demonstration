import ipaddress

def check_private_ip(ip_addr: str) -> bool:
    ip = ipaddress.ip_address(ip_addr)
    return ip.is_private
