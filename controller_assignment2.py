from pox.core import core
import pox.lib.packet as pkt
import pox.lib.packet.ethernet as eth
import pox.lib.packet.arp as arp
import pox.lib.packet.icmp as icmp
import pox.lib.packet.ipv4 as ip
import pox.openflow.libopenflow_01 as of
from pox.lib.util import dpidToStr
from pox.lib.addresses import EthAddr


log = core.getLogger()

# create table of what switch east host is on
switch_hosts = {}

# create table of known host ports for each switch
table={}

rules=[
# => you need now to add other rules to satisfy the assignment requirements. Notice that we will make decisions based on Ethernet address rather than IP address. Rate limiting is implemented by sending the pacet to the correct port and queue (the queues that you have specified in the topology file).
{'priority':100,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03', 'TCPPort':40, 'queue':1, 'drop':False}, # cap at 30 Mb/s
{'priority':100,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02', 'TCPPort':60, 'queue':1, 'drop':False}, # cap at 150 Mb/s
       
# ARP rule inserted for all ports outside those specifically mentioned in the assignment briefing
{'priority':40,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:03', 'queue':0, 'drop':False}, # ARP uncapped
{'priority':40,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:02', 'queue':0, 'drop':False}, # ARP uncapped

{'priority':60,'EthSrc':'00:00:00:00:00:01','EthDst':'00:00:00:00:00:04', 'queue':0, 'drop':False}, # uncapped
{'priority':60,'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:01', 'queue':None, 'drop':False}, # uncapped

{'priority':80,'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:04', 'queue':1, 'drop':False}, # cap at 200 Mb/s

{'priority':80,'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:04', 'queue':None, 'drop':True}, # blocked
{'priority':80,'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:03', 'queue':None, 'drop':True}, # blocked

{'priority':60,'EthSrc':'00:00:00:00:00:03','EthDst':'00:00:00:00:00:01', 'queue':None, 'drop':False}, # uncapped
{'priority':60,'EthSrc':'00:00:00:00:00:02','EthDst':'00:00:00:00:00:01', 'queue':None, 'drop':False}, # uncapped
{'priority':60,'EthSrc':'00:00:00:00:00:04','EthDst':'00:00:00:00:00:02', 'queue':0, 'drop':False}, # uncapped
]

    	
def launch():
    core.openflow.addListenerByName("ConnectionUp", _handle_ConnectionUp)
    core.openflow.addListenerByName("PacketIn",  _handle_PacketIn)
    log.info("Switch running.")

def _handle_ConnectionUp(event):
    sw = dpidToStr(event.dpid)
    log.info("Starting Switch %s", sw)
    msg = of.ofp_flow_mod(command = of.OFPFC_DELETE)
    event.connection.send(msg)


def _handle_PacketIn(event): # Ths is the main class where your code goes, it will be called every time a packet is sent from the switch to the controller

    dpid = event.connection.dpid
    sw=dpidToStr(dpid)
    inport = event.port     # this records the port from which the packet entered the switch
    eth_packet = event.parsed # this parses the incoming message as an Ethernet packet
    log.debug("Event: switch %s port %s packet %s" % (sw, inport, eth_packet)) # this is the way you can add debugging information to your text

    if eth_packet.src not in switch_hosts:
        switch_hosts[eth_packet.src] = sw

    ######################################################################################
    ############ CODE SHOULD ONLY BE ADDED BELOW  #################################

    # ==> write code here that associates the given port with the sending node using the source address of the incoming packet
    # ==> if available in the table this line determines the destination port of the incoming packet

    table[(dpid, eth_packet.src)] = event.port   # this associates the given port with the sending node using the source address of the incoming packet
    # log.debug("INFO: Table is as follow:\n %s" % (table))
    dst_port = table.get((dpid, eth_packet.dst)) # if available in the table this line determines the destination port of the incoming packet

    if dst_port is None and eth_packet.type == eth.ARP_TYPE and eth_packet.dst == EthAddr(b"\xff\xff\xff\xff\xff\xff"):
        # => in this case you want to create a packet so that you can send the message as a broadcast
        data_msg = of.ofp_packet_out(data = event.ofp)
        data_msg.actions.append(of.ofp_action_output(port=of.OFPP_ALL))
        event.connection.send(data_msg)

    for rule in rules: #now you are adding rules to the flow tables like before. First you check whether there is a rule match based on Eth source and destination
        if eth_packet.dst==EthAddr(rule['EthDst']) and eth_packet.src==EthAddr(rule['EthSrc']):
            log.debug("Event: found rule from source %s to dest  %s" % (eth_packet.src, eth_packet.dst))
            # => now you are adding rules to the flow tables like before. First you check whether there is a rule match based on Eth source and destination as in assignment 1, but you need to adapt this for the case of more than 1 switch
            flow_msg = of.ofp_flow_mod()
            flow_msg.priority = rule['priority']
            flow_msg.match.dl_dst = eth_packet.dst
            flow_msg.match.dl_src = eth_packet.src
            flow_msg.soft_timeout = 40

            # assign data message variable
            data_msg = of.ofp_packet_out()

            if 'TCPPort' not in rule: # Non-TCP packet

                if rule['drop'] is True:
                    event.connection.send(flow_msg)
                    event.connection.send(data_msg)
                    break # packet is dropped by not adding action
                elif rule['queue'] is not None and switch_hosts[eth_packet.dst] == sw: 
                    flow_msg.actions.append(of.ofp_action_enqueue(port=dst_port, queue_id=rule['queue']))
                    event.connection.send(flow_msg)
                    data_msg.data = event.ofp
                    data_msg.actions.append(of.ofp_action_enqueue(port=dst_port, queue_id=rule['queue']))
                    event.connection.send(data_msg)
                else:
                    flow_msg.actions.append(of.ofp_action_output(port = dst_port))
                    event.connection.send(flow_msg)
                    data_msg.data = event.ofp
                    data_msg.actions.append(of.ofp_action_output(port=dst_port))
                    event.connection.send(data_msg)

            else:  # TCP packet

                # extract IP packet header
                ip_packet = eth_packet.payload

                # check for IPV4 packet and TCP protocol respectively
                if eth_packet.type == '0x0800' and ip_packet.protocol == '0x06':
                    # match the destination TCP port
                    flow_msg.match.dl_type = eth.IP_TYPE
                    flow_msg.match.nw_proto = ip.TCP_PROTOCOL

                    # check for match with packet's actual TCP port
                    tcp_packet = ip_packet.payload

                    if tcp_packet.protocol == rule['TCPPort']:
                        flow_msg.match.tp_dst = rule['TCPPort']
                    else:
                        event.connection.send(flow_msg)
                        event.connection.send(data_msg)
                        return  # exit function to drop packet

                if rule['drop']:
                    event.connection.send(flow_msg)
                    event.connection.send(data_msg)
                    break # packet is dropped by setting output port to none (however this approach doesn't work with pox so just send and break)
                elif rule['queue'] is not None and switch_hosts[eth_packet.dst] == sw:
                    flow_msg.actions.append(of.ofp_action_enqueue(port=dst_port, queue_id=rule['queue']))
                    event.connection.send(flow_msg)
                    data_msg.data = event.ofp
                    data_msg.actions.append(of.ofp_action_enqueue(port=dst_port, queue_id=rule['queue']))
                    event.connection.send(data_msg)
                else:
                    flow_msg.actions.append(of.ofp_action_output(port=dst_port))
                    event.connection.send(flow_msg)
                    data_msg.data = event.ofp
                    data_msg.actions.append(of.ofp_action_output(port=dst_port))
                    event.connection.send(data_msg)
            
            break
