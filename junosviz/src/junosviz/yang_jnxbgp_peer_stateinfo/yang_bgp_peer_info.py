from ncclient import manager
from lxml import etree
import json
import time
from datetime import datetime

class BGPDataFetcher:
    def __init__(self, host, username, password, polling_interval):
        self.router = {
            "host": host,
            "port": "22",
            "username": username,
            "password": password
        }
        self.polling_interval = polling_interval

    def parse_bgp_peers(self, xml_data):
        root = etree.fromstring(xml_data.encode())
        peer_data_list = []

        for peer in root.xpath(".//bgp-peer"):
            peer_data = {
                "measurement": "bgp_yang_metrics",
                "tags": {
                    "peer_address": peer.findtext("peer-address"),
                    "peer_as": peer.findtext("peer-as"),
                    "peer_description": peer.findtext("description")
                },
                "fields": {
                    "input_messages": int(peer.findtext("input-messages")),
                    "output_messages": int(peer.findtext("output-messages")),
                    "route_queue_count": int(peer.findtext("route-queue-count")),
                    "flap_count": int(peer.findtext("flap-count")),
                    "elapsed_time_seconds": int(peer.find("elapsed-time").get("seconds")),
                    "peer_state": peer.findtext("peer-state")
                },
                "timestamp": datetime.now().isoformat()
            }

            for rib in peer.findall("bgp-rib"):
                rib_name = rib.findtext("name")
                if rib_name in ["inet.0", "inet6.0"]:
                    prefix = rib_name.replace(".", "_")
                    peer_data["fields"][f"{prefix}_active_prefix_count"] = int(rib.findtext("active-prefix-count"))
                    peer_data["fields"][f"{prefix}_received_prefix_count"] = int(rib.findtext("received-prefix-count"))
                    peer_data["fields"][f"{prefix}_accepted_prefix_count"] = int(rib.findtext("accepted-prefix-count"))
                    peer_data["fields"][f"{prefix}_suppressed_prefix_count"] = int(rib.findtext("suppressed-prefix-count"))

            peer_data_list.append(peer_data)

        return peer_data_list

    def fetch_bgp_data(self):
        with manager.connect(
            host=self.router["host"],
            port=self.router["port"],
            username=self.router["username"],
            password=self.router["password"],
            hostkey_verify=False,
            device_params={'name': 'junos'}
        ) as m:
            rpc = etree.Element("get-bgp-summary-information", xmlns="http://yang.juniper.net/junos/rpc/bgp")
            result = m.dispatch(rpc)
            xml_data = str(result)
            parsed_data = self.parse_bgp_peers(xml_data)
            return json.dumps(parsed_data, indent=2)

    def start_polling(self):
        try:
            while True:
                data = self.fetch_bgp_data()
                print("\nJSON Data for InfluxDB:\n", data)
                time.sleep(self.polling_interval)
        except KeyboardInterrupt:
            print("Polling stopped.")

# Example usage
if __name__ == "__main__":
    # Set the polling interval during object creation, e.g., 15 seconds
    fetcher = BGPDataFetcher(
        host="10.232.0.31",
        username="root",
        password="Helix#1991$",
        polling_interval=15  # Set polling interval here
    )
    fetcher.start_polling()
