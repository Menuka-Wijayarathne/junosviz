from pysnmp.hlapi.v3arch.asyncio import *
import asyncio
import httpx
import datetime
import uuid  # For generating a unique alert index

class BgpAcceptPrefixMonitor:
    def __init__(self, community, agent_ip, interval):
        self.community = community
        self.agent_ip = agent_ip
        self.interval = interval
        self.snmp_engine = SnmpEngine()
        self.peer_state_cache = {}

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

        # OIDs for peer state, received prefixes, remote peer address, and remote peer AS
        peer_state_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.1.1.1.2')
        peer_received_prefixes_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.6.2.1.8')
        remote_peer_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.1.1.1.11')
        remote_peer_as_oid = ObjectIdentity('1.3.6.1.4.1.2636.5.1.1.2.1.1.1.13')

        # Walk each OID
        peer_states = await self.walk_oid(target, peer_state_oid)
        peer_received_prefixes = await self.walk_oid(target, peer_received_prefixes_oid)
        remote_peers = await self.walk_oid(target, remote_peer_oid)
        remote_peer_as_values = await self.walk_oid(target, remote_peer_as_oid)

        # Build structured data
        device_data = {hostname: []}
        
        # Create a dictionary to store peer information based on peer_id
        peer_info = {}

        # Populate peer_info with data from remote_peers
        for oid, address in remote_peers.items():
            peer_id = oid.split('.')[-1]  # Last digit as peer_id
            peer_info[peer_id] = {
                'remote_peer_address': address,
                'remote_peer_as': 'Unknown',  # Will update below if available
                'ipv4_prefixes': None,
                'ipv6_prefixes': None,
                'peer_state': 'Unknown'  # Will update below if available
            }

        # Update remote_peer_as in peer_info
        for oid, as_value in remote_peer_as_values.items():
            peer_id = oid.split('.')[-1]  # Last digit as peer_id
            print(peer_id)
            if peer_id in peer_info:
                peer_info[peer_id]['remote_peer_as'] = int(as_value) if hasattr(as_value, 'prettyPrint') else 'Unknown'

        # Update peer_state in peer_info
        for oid, state in peer_states.items():
            peer_id = oid.split('.')[-1]  # Last digit as peer_id
            print(peer_id)
            if peer_id in peer_info:
                #print(int(state))
                # Assume peer_state is an integer; add check if needed
                peer_info[peer_id]['peer_state'] = int(state.prettyPrint()) if hasattr(state, 'prettyPrint') else int(state)

        # Match prefixes based on peer_id and type (IPv4 or IPv6)
        for oid, prefixes in peer_received_prefixes.items():
            prefix_parts = oid.split('.')[-3:]  # Last three parts (e.g., 1.1.1)
            peer_id = prefix_parts[0]  # First part corresponds to peer_id
            print(peer_id)
            prefix_type = '.'.join(prefix_parts[1:])  # 1.1 for IPv4, 2.1 for IPv6

            if peer_id in peer_info:
                if prefix_type == '1.1':
                    peer_info[peer_id]['ipv4_prefixes'] = int(prefixes)
                elif prefix_type == '2.1':
                    peer_info[peer_id]['ipv6_prefixes'] = int(prefixes)

        # Organize device_data based on peer_info
        for peer_id, info in peer_info.items():
            # Process the remote peer address to human-readable format if needed
            remote_address = info['remote_peer_address']
            if isinstance(remote_address, OctetString):
                if len(remote_address) == 4:  # IPv4
                    remote_address = '.'.join(str(b) for b in remote_address.asNumbers())
                elif len(remote_address) == 16:  # IPv6
                    remote_address = ':'.join(f"{b:02x}{c:02x}" for b, c in zip(remote_address.asNumbers()[::2], remote_address.asNumbers()[1::2]))
            else:
                remote_address = 'Unknown'

            # Append each peer's data to the device_data structure
            device_data[hostname].append({
                'peer_id': peer_id,
                'peer_state': info['peer_state'],
                'ipv4_prefixes': info['ipv4_prefixes'] if info['ipv4_prefixes'] is not None else 0,
                'ipv6_prefixes': info['ipv6_prefixes'] if info['ipv6_prefixes'] is not None else 0,
                'remote_peer_address': remote_address,
                'remote_peer_as': info['remote_peer_as']
            })

        return device_data

    async def start_polling(self):
        while True:
            data = await self.poll_data()
            print("Polling Result:", data)
            await asyncio.sleep(self.interval)

# Usage example:
if __name__ == "__main__":
    monitor = BgpAcceptPrefixMonitor(
        community='HeartInt_Ld5s2024$',
        agent_ip='10.232.0.31',
        interval=300,  # Polling every 5 minutes
    )
    asyncio.run(monitor.start_polling())