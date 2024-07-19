# Network IDS System and Log Monitoring Implementation

## Overview

This project involves the implementation of a Network Intrusion Detection System (NIDS) and Host Intrusion Detection System (HIDS) using Wazuh and Suricata. The setup includes active response and file integrity checking to enhance security and detect potential threats efficiently.

## Features

1. **System Vulnerability Checker**: Scans and identifies system vulnerabilities.
2. **File Integrity Check**: Monitors and reports changes to files.
3. **Network Intrusion Detection System (NIDS)**: Utilizes Suricata and emerging threats rule sets to detect network-based attacks.
4. **Host Intrusion Detection System (HIDS)**: Employs the Wazuh agent to monitor host activities and detect suspicious behaviors.
5. **Active Response**: Automatically responds to detected attacks to mitigate potential damage.

## Technologies Used

- **Wazuh**: For HIDS and log monitoring.
- **Suricata**: For NIDS.
- **Docker**: To containerize and deploy the Wazuh components.
- **Emerging Threats**: For Suricata rule sets.
- **Ubuntu Servers**: As the host operating system.

## Installation and Setup

### Prerequisites

- Ubuntu Server installed on all involved machines.
- Docker installed on the Ubuntu Server.

### Step-by-Step Instructions

#### 1. Setup Docker on the Ubuntu Server and Install Wazuh

1. Install Docker on your Ubuntu server:
    ```sh
    sudo apt-get update
    sudo apt-get upgrade
    sysctl -w vm.max_map_count=262144
    curl -sSL https://get.docker.com/ | sh
    systemctl start docker
    curl -L "https://github.com/docker/compose/releases/download/v2.12.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    chmod +x /usr/local/bin/docker-compose
    docker-compose --version
    ```

2. Pull the Wazuh Docker image and run it (single-node or multi-node configuration):
    ```sh
    git clone https://github.com/wazuh/wazuh-docker.git -b v4.7.5
    cd wazuh-docker/single-node
    docker-compose -f generate-indexer-certs.yml run --rm generator
    docker-compose up -d
    ```
   1. Configure ossec.conf file to detect file integrity checks, and vulnerability checks, and log all possible logs in JSON and normal log format.
   2. Configure the file to enable active response. You can create your own rule sets and active response sets. For this demo, I am using Brute force ssh login schema
#### 2. Setup Suricata on Another Ubuntu Server

1. Install Suricata:
    ```sh
    git clone https://github.com/nn-df/suricata-installation.git
    cd suricata-installation
    sudo bash suricata.sh
    
    ```

2. Configure Suricata to read rules from the Emerging Threats library:
    ```sh
    cd /tmp/ && curl -LO https://rules.emergingthreats.net/open/suricata-6.0.8/emerging.rules.tar.gz
    sudo tar -xvzf emerging.rules.tar.gz && sudo mv rules/*.rules /etc/suricata/rules/
    sudo chmod 640 /etc/suricata/rules/*.rules
    ```
3. Configure suricata setting to read the rule sets:
   ```sh
      HOME_NET: "<UBUNTU_IP>"
      EXTERNAL_NET: "any"

      default-rule-path: /etc/suricata/rules
      rule-files:
      - "*.rules"

      # Global stats configuration
      stats:
      enabled: Yes

      # Linux high speed capture support
         af-packet:
      - interface: your capture card id
   ```
5. Install and configure the Wazuh agent to get logs from Suricata:
    ```sh
    By using the add agent feature in Wazuh dashboard, add the machine to agent list
    ```

    Configure the agent by editing the `/var/ossec/etc/ossec.conf` file to include Suricata log paths.

#### 3. Setup an Attack Box

1. Prepare an attack box to test the system's efficiency and response capabilities. This can be done using Kali Linux or any other preferred penetration testing distribution.

## Usage

- **Monitoring**: Access the Wazuh dashboard to monitor the system's status, check alerts, and review logs.
- **Active Response**: Configure active responses in Wazuh to automate defensive actions when an attack is detected.
- **File Integrity**: Review file integrity reports to detect unauthorized changes.

## Screenshots
1. File integrity check
![Screenshot 2024-07-18 140351](https://github.com/user-attachments/assets/237fafcf-670f-40bc-bc42-756a17b0994c)
2. Suricata Log on excessive transmissions
![Screenshot 2024-07-18 154023](https://github.com/user-attachments/assets/2e4f7841-ec0a-4dc5-98d3-1ad733ce2737)
![Screenshot 2024-07-18 154053](https://github.com/user-attachments/assets/3d876beb-9ba4-4180-99e8-fd75ed470f70)
3. Suricata log on Nmap Scan
![Screenshot 2024-07-18 160821](https://github.com/user-attachments/assets/c34c7cf1-1e37-4c65-ba6f-0508cd1187f0)
![Screenshot 2024-07-18 162919](https://github.com/user-attachments/assets/aecd1f74-eccd-43d2-b4f2-fa3760b015f6)
4. System vulnerability Checker
![Screenshot 2024-07-18 185140](https://github.com/user-attachments/assets/da40908f-0637-46ba-ba5e-263c68525363)
![Screenshot 2024-07-18 185220](https://github.com/user-attachments/assets/8420c53a-a9db-45ad-98be-5dcec939a275)
5. Checking for audits
![Screenshot 2024-07-18 185855](https://github.com/user-attachments/assets/9bce76ff-4a03-46f4-82fb-7710b87f84cb)
6. Detecting brute force ssh attack from attack box on the ubuntu server.
![Screenshot 2024-07-18 191920](https://github.com/user-attachments/assets/92776df2-f5f7-4849-ab24-bd9217415eb7)
![Screenshot 2024-07-18 192017](https://github.com/user-attachments/assets/4f410530-08a4-4fec-983b-094e441bd69f)


# Intrusion Detection System (IDS) Demo using Python and Wire Shark

This project is an Intrusion Detection System (IDS) that captures and analyzes network packets to detect suspicious activities. It uses various techniques to identify anomalies, log them, and report them to a remote server.
## Technological Stack
<img src="https://img.shields.io/badge/python%20-%2314354C.svg?&style=for-the-badge&logo=python&logoColor=yellow"/> <img src="https://img.shields.io/badge/wireshark%20-%2314354C.svg?&style=for-the-badge&logo=wireshark&logoColor=blue"/>




## Table of Contents
- [Test Overview](#testcase)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [File Descriptions](#file-descriptions)
- [License](#license)
- [Work in Progress](#FutureWork)
- [Contact Me](#contact-me)

## Test Overview

For testing purposes, I have used the canary token to generate a test URL generating requests
### sample data generated in log-file
![image](https://github.com/Akito7011/IDS/assets/70007965/99674cab-993e-4f94-8555-76e7b49c3c59)


## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Akito7011/IDS-with-docker.git
   cd IDS-with-docker
   ```

2. **Install the required dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   - Create a `.env` file in the root directory.
   - Add the following environment variable:
     ```plaintext
     SERVER_URL=your_server_url_here
     ```

## Usage

1. **Configure the IDS:**
   - Edit the `config.py` file to set your network interface and log file.

2. **Run the IDS:**
   ```bash
   python main.py
   ```

## Configuration

Configuration is managed through the `config.py` file and `.env` file.

- `config.py`:
  ```python
  import os
  from dotenv import load_dotenv
  import netifaces

  load_dotenv()

  SERVER_URL = os.getenv('SERVER_URL')
  INTERFACE = "\\Device\\NPF_" + str(netifaces.gateways()['default'][netifaces.AF_INET][1])
  LOG_FILE = 'ids.log'
  ```
  - `SERVER_URL`: URL of the server to report suspicious activities.
  - `INTERFACE`: Network interface to capture packets.
  - `LOG_FILE`: File to log suspicious activities.

## File Descriptions

- **config.py**: Configuration file that loads environment variables and sets network interface and log file.

- **main.py**: Entry point of the IDS. Initializes and starts packet capture.

- **packet_processing.py**: Contains the `IDS` class responsible for packet capture, filtering, and analysis.

- **server_communication.py**: Handles communication with the remote server. Defines `Packet` and `ServerCall` classes.

- **suspiciousActivity.py**: Contains functions to check for suspicious activities, unusual ports, unusual traffic, protocol violations, and failed connections.

- **utils.py**: Utility functions. Currently includes a function to check if an IP address is private.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

# Contact Me

If you have any questions, or suggestions, or just want to connect, feel free to reach out to me through the following channels:

## 📧 Email
[![Email](https://img.shields.io/badge/Email-mailto%3Atanishqtanwar1976%40gmail.com-blue?logo=gmail&logoColor=white)](mailto:tanishqtanwar1976@gmail.com)

## 💼 LinkedIn
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/tanishq-tanwar)

---

I appreciate your interest, and I look forward to connecting with you!


