# junosviz
A Python package for BGP monitoring and state analysis.
`junosviz` is a Python package for monitoring and alerting BGP states and metrics of juniper  using snmp, NETCONF, and gNMI.

## Features
- Monitor BGP peer state.
- Return Data can be easily feeded into timeseries database like influx db(so you can easily visulize it using grafana)
- Retrieve bgp metrics using Juniper-specific MIBs,openconfig yang models,ietf and juniper native yang models
- Generate alerts for BGP state changes.(in built bettertack alerting method)
- Support bgp next hop encoding capablity.
- Tested on junos 23.4R2-S2.1
- Easily trigger alerts using betterstack or using grafana
![image](https://github.com/user-attachments/assets/a08c95f3-8c07-4e35-ab33-9c8155c1ddc8)

## Installation
Install `junosviz` via pip:
```bash
pip install junosviz

##package and the modules

1.how to use method BgpPeerStateMonitor in module bgp_peer_state_monitor

import asyncio
from junosviz.bgp_jnxBgpM2PeerState_alert.bgp_peer_state_monitor import BgpPeerStateMonitor

async def main():
    monitor = BgpPeerStateMonitor(
        community='snmp community v2',
        agent_ip='ip address of the snmp client',
        interval=300,  desired polling interval
        webhook_url='https://uptime.betterstack.com/api/v1/incoming-webhook/8reBKaETXnEBhbp2v49m1DJp'  # Replace with actual webhook URL
    )
    await monitor.start_polling()

asyncio.run(main())

once you create the object and invoke the method, below attributes will be passed to betterstack webhook as encoded as json parameters.

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.webhook_url,
                json={
                    "alert_type": "BGP Peer State Alert",
                    "peer_state": peer_state,
                    "instance_id": instance_id,
                    "remote_peer_address": remote_peer_address,
                    "remote_peer_as": remote_peer_as,
                    "timestamp": timestamp,
                    "index": str(alert_index)
                }
            )

2.how to use method BGPDataFetcher in module yang_bgp_peer_info
here , i desinged the BGPDataFetcher to return following the data in json format so we can easily feed them into time series databases.(influx db usually)

 for rib in peer.findall("bgp-rib"):
                rib_name = rib.findtext("name")
                if rib_name in ["inet.0", "inet6.0"]:
                    prefix = rib_name.replace(".", "_")
                    peer_data["fields"][f"{prefix}_active_prefix_count"] = int(rib.findtext("active-prefix-count"))
                    peer_data["fields"][f"{prefix}_received_prefix_count"] = int(rib.findtext("received-prefix-count"))
                    peer_data["fields"][f"{prefix}_accepted_prefix_count"] = int(rib.findtext("accepted-prefix-count"))
                    peer_data["fields"][f"{prefix}_suppressed_prefix_count"] = int(rib.findtext("suppressed-prefix-count"))

you can integrate nornir framework and integrate this method effectively with your junos device

example code:

from nornir import InitNornir
from nornir_utils.plugins.functions import print_result
from nornir.core.task import Task, Result
from bgp_monitoring.yang_jnxbgp_peer_stateinfo.yang_bgp_peer_info import BGPDataFetcher
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import SYNCHRONOUS
import json
import time

# InfluxDB configuration
INFLUXDB_URL = "http://localhost:8086"
INFLUXDB_TOKEN = "ZqWUabsv7KxKEkr_6l9GCJZnmPgGexh-KtXJoaG5PFTzZzPrdzLI-e8FpoLne_BJaNQhkH5kwpPocLK_9NtL6w=="
INFLUXDB_ORG = "heart_internet"
INFLUXDB_BUCKET = "bgp_yang"
POLLING_INTERVAL = 15  # Define the polling interval here

def yang_bgp(task: Task) -> Result:
    host = task.host
    
    # Initialize the BGPDataFetcher for each host
    fetcher = BGPDataFetcher(
        host=host.hostname,
        username=host.username,
        password=host.password,
        polling_interval=POLLING_INTERVAL
    )
    
    # Set up InfluxDB client
    client = InfluxDBClient(url=INFLUXDB_URL, token=INFLUXDB_TOKEN, org=INFLUXDB_ORG)
    write_api = client.write_api(write_options=SYNCHRONOUS)
    
    try:
        # Fetch BGP data for the host
        data_json = fetcher.fetch_bgp_data()
        data = json.loads(data_json)

        # Write fetched data to InfluxDB
        for entry in data:
            point = (
                Point(entry["measurement"])
                .tag("peer_address", entry["tags"]["peer_address"])
                .tag("peer_as", entry["tags"]["peer_as"])
                .tag("peer_description", entry["tags"]["peer_description"])
            )

            for field, value in entry["fields"].items():
                point = point.field(field, value)

            # Use the parsed timestamp or set InfluxDB to use the server time
            point = point.time(entry["timestamp"])
            write_api.write(bucket=INFLUXDB_BUCKET, record=point)

        return Result(
            host=task.host,
            result=f"Data successfully written to InfluxDB for {host.name}"
        )
    except Exception as e:
        return Result(
            host=task.host,
            failed=True,
            exception=e
        )
    finally:
        client.close()

# Main function to initialize Nornir and run tasks continuously
def main():
    nr = InitNornir(config_file="/home/dco/nms/nornir/config.yaml")
    filtered = nr.filter(role="dfz")
    
    try:
        while True:
            print(f"Running tasks for filtered hosts: {list(filtered.inventory.hosts.keys())}")
            result = filtered.run(task=yang_bgp)
            print_result(result)
            
            # Wait for the polling interval
            time.sleep(POLLING_INTERVAL)
    except KeyboardInterrupt:
        print("Polling stopped.")

if __name__ == "__main__":
    main()
