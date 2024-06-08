# Intrusion Detection System (IDS) with Docker function

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

## Work in Progress

| Feature/Task                             | Status       | Description                                                                 |
|------------------------------------------|--------------|-----------------------------------------------------------------------------|
| CSV import for suspicious IPs and ports  | 🛠️           | Allow importing suspicious IPs and ports from a CSV file.                   |
| Scaling the Project using docker and     | 🛠️           | Testing, currently unstable.                              |
| Real-time dashboard                      | 🚀           | Develop a real-time dashboard for monitoring detected activities.           |

### Legend

- ✅ Completed
- 📝 In Progress
- 🛠️ In Progress
- 🚧 Planned
- 🚀 Planned
---

Feel free to contribute to this project by opening issues or submitting pull requests.

# Contact Me

If you have any questions, or suggestions, or just want to connect, feel free to reach out to me through the following channels:

## 📧 Email
[![Email](https://img.shields.io/badge/Email-mailto%3Atanishqtanwar1976%40gmail.com-blue?logo=gmail&logoColor=white)](mailto:tanishqtanwar1976@gmail.com)

## 💼 LinkedIn
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin&logoColor=white)](https://www.linkedin.com/in/tanishq-tanwar)

---

I appreciate your interest, and I look forward to connecting with you!


