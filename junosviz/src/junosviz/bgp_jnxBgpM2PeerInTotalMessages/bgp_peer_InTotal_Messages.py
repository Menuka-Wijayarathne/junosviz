from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
import datetime

class BgpPeerInMessagesMonitor:
    def __init__(self, community, agent_ip, interval):
        self.community = community
        self.agent_ip = agent_ip
        self.interval = interval
        self.snmp_engine = SnmpEngine()
        self.peer_message_in_cache = {}  # Cache to store previous in-message counts for each instance ID

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
        peer_in_messages_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.6.1.1.3')
        
        # Walk each OID
        peer_states = await self.walk_oid(target, peer_state_oid)
        remote_peers = await self.walk_oid(target, remote_peer_oid)
        remote_peer_as_values = await self.walk_oid(target, remote_peer_as_oid)
        peer_in_messages = await self.walk_oid(target, peer_in_messages_oid)
        
        # Build structured data
        device_data = {hostname: []}
        for oid, state in peer_states.items():
            instance_id = oid[len(str(peer_state_oid)):]
            remote_address_oid = f'{remote_peer_oid}{instance_id}'
            remote_as_oid_str = f'{remote_peer_as_oid}{instance_id}'
            peer_in_messages_str = f'{peer_in_messages_oid}{instance_id}'

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

            # Retrieve in-messages count
            peer_in_messages_count = peer_in_messages.get(peer_in_messages_str, 'Unknown')
            if hasattr(peer_in_messages_count, 'prettyPrint'):
                peer_in_messages_count = int(peer_in_messages_count.prettyPrint())

            # Calculate the incremental change in message count
            previous_count = self.peer_message_in_cache.get(instance_id, {}).get('in_message_count', 0)
            increment = peer_in_messages_count - previous_count if previous_count else 0
            # Update the cache with the current count for next poll
            self.peer_message_in_cache[instance_id] = {'in_message_count': peer_in_messages_count}

            timestamp = datetime.datetime.now().isoformat()  # Set the timestamp for the event

            # Append data to the device structure
            device_data[hostname].append({
                'instance_id': instance_id,
                'peer_state': int(state),
                'remote_peer_address': remote_address,
                'remote_peer_as': remote_as,
                'in_message_count': peer_in_messages_count,
                'increment': increment,  # Include the calculated increment
                'timestamp': timestamp
            })

        return device_data

    async def start_polling(self):
        while True:
            data = await self.poll_data()
            print("Polling Result:", data)
            await asyncio.sleep(self.interval)

# Usage example
if __name__ == "__main__":
    monitor = BgpPeerInMessagesMonitor(
        community='HeartInt_Ld5s2024$',
        agent_ip='10.232.0.31',
        interval=10  # Polling every 5 minutes
    )
    asyncio.run(monitor.start_polling())
