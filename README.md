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

## how to use package and the modules

*how to use method BgpPeerStateMonitor in module bgp_peer_state_monitor

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
