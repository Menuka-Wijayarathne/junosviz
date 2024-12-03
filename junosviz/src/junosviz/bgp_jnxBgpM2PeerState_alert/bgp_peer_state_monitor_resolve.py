from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
import httpx
import datetime
import uuid  # For generating a unique alert index

class BgpPeerStateMonitor:
    def __init__(self, community, agent_ip, interval, webhook_url):
        self.community = community
        self.agent_ip = agent_ip
        self.interval = interval
        self.snmp_engine = SnmpEngine()
        self.webhook_url = webhook_url  # Webhook URL for Better Stack
        self.peer_state_cache = {}  # Cache to store previous states and alert information

    async def get_hostname(self, target):
        hostname_oid = ObjectIdentity('1.3.6.1.2.1.1.5.0')
        response = await get_cmd(
            self.snmp_engine,
            CommunityData(self.community),
            target,
            ContextData(),
            ObjectType(hostname_oid)
        )
        errorIndication, errorStatus, errorIndex, varBinds = response
        if errorIndication:
            print("Error retrieving hostname:", errorIndication)
            return None
        elif errorStatus:
            print(f"Error Status at {errorIndex}: {errorStatus.prettyPrint()}")
            return None
        else:
            return str(varBinds[0][1])

    async def walk_oid(self, target, base_oid):
        data = {}
        next_oid = base_oid
        
        while next_oid is not None:
            response = await next_cmd(
                self.snmp_engine,
                CommunityData(self.community),
                target,
                ContextData(),
                ObjectType(next_oid)
            )
            errorIndication, errorStatus, errorIndex, varBinds = response
            if errorIndication:
                print("Error during SNMP walk:", errorIndication)
                break
            elif errorStatus:
                print(f"Error Status at {errorIndex}: {errorStatus.prettyPrint()}")
                break
            else:
                for varBind in varBinds:
                    oid, value = varBind
                    if str(oid).startswith(str(base_oid)):
                        data[str(oid)] = value
                        next_oid = oid
                    else:
                        next_oid = None
                        break
        return data

    async def poll_data(self):
        target = await UdpTransportTarget.create((self.agent_ip, 161))
        
        # Get hostname
        hostname = await self.get_hostname(target)
        if not hostname:
            print("Failed to retrieve hostname.")
            return

        # OIDs for peer state, remote peer address, and remote peer AS
        peer_state_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2')
        remote_peer_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.1.1.1.11')
        remote_peer_as_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.1.1.1.13')

        # Walk each OID
        peer_states = await self.walk_oid(target, peer_state_oid)
        remote_peers = await self.walk_oid(target, remote_peer_oid)
        remote_peer_as_values = await self.walk_oid(target, remote_peer_as_oid)

        # Build structured data
        device_data = {hostname: []}
        for oid, state in peer_states.items():
            instance_id = oid[len(str(peer_state_oid)):]
            remote_address_oid = f'{remote_peer_oid}{instance_id}'
            print(remote_address_oid)
            remote_as_oid_str = f'{remote_peer_as_oid}{instance_id}'

            # Retrieve remote peer address
            remote_address = remote_peers.get(remote_address_oid, 'Unknown')
            if isinstance(remote_address, OctetString):
                if len(remote_address) == 4:  # IPv4
                    remote_address = '.'.join(str(b) for b in remote_address.asNumbers())
                elif len(remote_address) == 16:  # IPv6
                    remote_address = ':'.join(f"{b:02x}{c:02x}" for b, c in zip(remote_address.asNumbers()[::2], remote_address.asNumbers()[1::2]))

            # Retrieve remote peer AS
            remote_as = remote_peer_as_values.get(remote_as_oid_str, 'Unknown')
            if hasattr(remote_as, 'prettyPrint'):
                remote_as = int(remote_as.prettyPrint())

            # Get previous state and alert info from cache (default to {'state': 6, 'alerted': False, 'alert_id': None})
            previous_state_data = self.peer_state_cache.get(instance_id, {'state': 6, 'alerted': False, 'alert_id': None})
            previous_state = previous_state_data['state']
            alerted = previous_state_data['alerted']
            alert_id = previous_state_data['alert_id']

            # Append data to the device structure
            device_data[hostname].append({
                'instance_id': instance_id,
                'peer_state': int(state),
                'remote_peer_address': remote_address,
                'remote_peer_as': remote_as
            })

            # Check for state changes and manage alert triggering/resolution
            if int(state) != 6:
                if previous_state == 6 and not alerted:
                    # Trigger an alert and generate a new alert_id
                    alert_id = uuid.uuid4()
                    await self.trigger_better_stack_alert(
                        instance_id=instance_id,
                        alert_id=alert_id,
                        peer_state=int(state),
                        remote_peer_address=remote_address,
                        remote_peer_as=remote_as
                    )
                    # Update the peer state to mark the alert as triggered
                    self.peer_state_cache[instance_id] = {'state': int(state), 'alerted': True, 'alert_id': alert_id}
                else:
                    # Update only the state without triggering another alert
                    self.peer_state_cache[instance_id]['state'] = int(state)

            elif int(state) == 6:
                if previous_state != 6:
                    # Resolve the alert if the state goes back to 6
                    await self.resolve_better_stack_alert(instance_id, alert_id)
                # Update the peer state to 6 and clear the alert flag and alert_id
                self.peer_state_cache[instance_id] = {'state': 6, 'alerted': False, 'alert_id': None}

        return device_data

    async def trigger_better_stack_alert(self, instance_id, alert_id, peer_state, remote_peer_address, remote_peer_as):
        timestamp = datetime.datetime.now().isoformat()

        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.webhook_url,
                json={
                    "alert_type": "BGP Peer State Alert",
                    "alert_id": str(alert_id),
                    "instance_id": instance_id,
                    "peer_state": peer_state,
                    "remote_peer_address": remote_peer_address,
                    "remote_peer_as": remote_peer_as,
                    "timestamp": timestamp
                }
            )
            if response.status_code == 200:
                print(f"Alert sent to Better Stack for instance_id {instance_id}")
            else:
                print(f"Failed to send alert: {response.status_code} - {response.text}")

    async def resolve_better_stack_alert(self, instance_id, alert_id):
        # Send request to resolve the alert in Better Stack using the alert_id
        async with httpx.AsyncClient() as client:
            response = await client.post(
                self.webhook_url,
                json={
                    "alert_type": "BGP Peer State Resolved",
                    "alert_id": str(alert_id),
                    "instance_id": instance_id
                }
            )
            if response.status_code == 200:
                print(f"Alert resolved in Better Stack for instance_id {instance_id}")
            else:
                print(f"Failed to resolve alert: {response.status_code} - {response.text}")

    async def start_polling(self):
        while True:
            data = await self.poll_data()
            print("Polling Result:", data)
            await asyncio.sleep(self.interval)
