import json
import base64
import logging
import requests

class Packet:
    def __init__(self, time_stamp: str = '', ipsrc: str = '', ipdst: str = '', 
                 srcport: int = 0, dstport: int = 0, transport_layer: str = '', highest_layer: str = ''):
        self.time_stamp = time_stamp
        self.ipsrc = ipsrc
        self.ipdst = ipdst
        self.srcport = srcport
        self.dstport = dstport
        self.transport_layer = transport_layer
        self.highest_layer = highest_layer

class ServerCall:
    def __init__(self, url: str):
        self.url = url

    def report_message(self, message: Packet):
        try:
            bottle = json.dumps(message.__dict__)
            json_string = bottle.encode('ascii')
            b64 = base64.b64encode(json_string)
            json_payload = b64.decode('utf8').replace("'", '"')
            decoded_json_string = base64.b64decode(b64).decode('utf8')
            logging.info(f"Reporting message (Encoded Message): {json_payload}")
            logging.info(f"Reporting message (Decoded Message): {decoded_json_string}")
            response = requests.post(self.url, data=json_payload)  # Send the data to the Canary token URL
            response.raise_for_status()  # Raise an HTTPError if the HTTP request returned an unsuccessful status code
        except requests.exceptions.RequestException as e:
            logging.error(f"Error reporting message: {e}")
