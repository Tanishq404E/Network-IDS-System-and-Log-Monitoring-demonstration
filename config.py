import os
from dotenv import load_dotenv
import netifaces

load_dotenv()

SERVER_URL = os.getenv('SERVER_URL')
INTERFACE = "\\Device\\NPF_" + str(netifaces.gateways()['default'][netifaces.AF_INET][1])
LOG_FILE = 'ids.log'
