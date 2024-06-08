from packet_processing.packet_processing import IDS
import config

def main():
    ids = IDS(config.SERVER_URL, config.INTERFACE, config.LOG_FILE)
    ids.start_capture()

if __name__ == "__main__":
    main()
