packets = [
    {"source_ip": "192.168.1.12", "dest_ip": "192.168.1.22", "protocol": "TCP", "payload": "Normal data"},
    {"source_ip": "192.168.1.11", "dest_ip": "192.168.1.20", "protocol": "UDP", "payload": "Suspicious data"},
    {"source_ip": "192.168.1.4", "dest_ip": "192.168.1.9", "protocol": "TCP", "payload": "Normal data"},
    {"source_ip": "192.168.1.31", "dest_ip": "192.168.1.5", "protocol": "TCP", "payload": "Malicious code"},
    {"source_ip": "192.168.1.1", "dest_ip": "192.168.1.6", "protocol": "TCP", "payload": "Intrusion detected: SQL injection attempt!"},
]
class FSM:
    def __init__(self):
        self.state = "INIT"
        self.alert = False
        self.last_protocol = None
        self.unauthorized_alert = False

        # Use full file paths for the source and destination files
        source_file_path = r"C:\Users\elsetouhy21\OneDrive\Desktop\Grad\SAL SOURCE.txt"
        destination_file_path = r"C:\Users\elsetouhy21\OneDrive\Desktop\Grad\SAL DESTINATION.txt"

        # Load authorized sources and destinations from the specified files
        self.authorized_sources = self.load_ips_from_file(source_file_path)
        self.authorized_destinations = self.load_ips_from_file(destination_file_path)

    def load_ips_from_file(self, file_path):
        """Load IPs from a text file."""
        try:
            with open(file_path, "r") as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return []

  
    def load_ips_from_file(self, file_path):
        """Load IPs from a text file."""
        try:
            with open(file_path, "r") as file:
                return [line.strip() for line in file.readlines()]
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            return []

    def authorize(self, packet):
        """Check if both the source and destination IPs are authorized in both lists."""
        source_authorized = packet["source_ip"] in self.authorized_sources and packet["source_ip"] in self.authorized_destinations
        destination_authorized = packet["dest_ip"] in self.authorized_sources and packet["dest_ip"] in self.authorized_destinations
        return source_authorized and destination_authorized

    def transition(self, packet):
        print(f"Current State: {self.state}, Incoming Packet: {packet}")

        if self.state == "INIT":
            if self.authorize(packet):
                print("Authorization successful; source and destination are authorized.")
                self.state = "CHECK_PAYLOAD"  
            else:
                print("Authorization failed; source or destination unauthorized. Remaining in INIT state.\n")
                self.unauthorized_alert = True  
                return 

        if self.state == "CHECK_PAYLOAD":
            if self.last_protocol == "UDP" and packet["protocol"] == "TCP":
                self.alert = True
                print("ALERT: Suspicious activity detected! Protocol changed from UDP to TCP.\n")

            if "Malicious code" in packet["payload"]:
                self.alert = True
                print("ALERT: Malicious payload detected!\n")
            elif "Suspicious data" in packet["payload"]:
                self.alert = True
                print("ALERT: Suspicious payload detected!\n")
            elif "Intrusion detected" in packet["payload"]:
                self.alert = True
                print("ALERT: Intrusion detected in payload!\n") 
            else:
                print("Payload is clean.\n")

            self.last_protocol = packet["protocol"]
            self.state = "INIT"
    def check_state(self):
        print(f"Current FSM State: {self.state}\n")

    def check_alert(self):
        if self.alert:
            print("FINAL ALERT: Intrusion detected!")
        else:
            print("No intrusion detected.")
        
        if self.unauthorized_alert:
            print("FINAL ALERT: Unauthorized action detected!")
# Process each packet
fsm = FSM()
for packet in packets:
    fsm.transition(packet)
# Instantiate the FSM
fsm.check_alert()