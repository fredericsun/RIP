package edu.wisc.cs.sdn.vnet.rt;

import edu.wisc.cs.sdn.vnet.Device;
import edu.wisc.cs.sdn.vnet.DumpFile;
import edu.wisc.cs.sdn.vnet.Iface;

import net.floodlightcontroller.packet.*;

import java.util.List;

/**
 * @author Aaron Gember-Jacobson and Anubhavnidhi Abhashkumar
 */
public class Router extends Device
{	
	/** Routing table for the router */
	private RouteTable routeTable;
	
	/** ARP cache for the router */
	private ArpCache arpCache;
	
	/**
	 * Creates a router for a specific host.
	 * @param host hostname for the router
	 */
	public Router(String host, DumpFile logfile)
	{
		super(host,logfile);
		this.routeTable = new RouteTable();
		this.arpCache = new ArpCache();
	}
	
	/**
	 * @return routing table for the router
	 */
	public RouteTable getRouteTable()
	{ return this.routeTable; }
	
	/**
	 * Load a new routing table from a file.
	 * @param routeTableFile the name of the file containing the routing table
	 */
	public void loadRouteTable(String routeTableFile)
	{
		if (!routeTable.load(routeTableFile, this))
		{
			System.err.println("Error setting up routing table from file "
					+ routeTableFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static route table");
		System.out.println("-------------------------------------------------");
		System.out.print(this.routeTable.toString());
		System.out.println("-------------------------------------------------");
	}
	
	/**
	 * Load a new ARP cache from a file.
	 * @param arpCacheFile the name of the file containing the ARP cache
	 */
	public void loadArpCache(String arpCacheFile)
	{
		if (!arpCache.load(arpCacheFile))
		{
			System.err.println("Error setting up ARP cache from file "
					+ arpCacheFile);
			System.exit(1);
		}
		
		System.out.println("Loaded static ARP cache");
		System.out.println("----------------------------------");
		System.out.print(this.arpCache.toString());
		System.out.println("----------------------------------");
	}

	/**
	 * Handle an Ethernet packet received on a specific interface.
	 * @param etherPacket the Ethernet packet that was received
	 * @param inIface the interface on which the packet was received
	 */
	public void handlePacket(Ethernet etherPacket, Iface inIface)
	{
		System.out.println("*** -> Received packet: " +
                etherPacket.toString().replace("\n", "\n\t"));
		
		/********************************************************************/
		/* TODO: Handle packets                                             */
		
		switch(etherPacket.getEtherType())
		{
		case Ethernet.TYPE_IPv4:
			this.handleIpPacket(etherPacket, inIface);
			break;
		// Ignore all other packet types, for now
		}
		
		/********************************************************************/
	}
	
	private void handleIpPacket(Ethernet etherPacket, Iface inIface)
	{
		// Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        System.out.println("Handle IP packet");

        // Verify checksum
        short origCksum = ipPacket.getChecksum();
        ipPacket.resetChecksum();
        byte[] serialized = ipPacket.serialize();
        ipPacket.deserialize(serialized, 0, serialized.length);
        short calcCksum = ipPacket.getChecksum();
        if (origCksum != calcCksum)
        { return; }

        /* RIP operation part */

        // note that the following three line is just to transfer '224.0.0.9' into integer. Do not know whether it is
        // correct or not but it is the only way I come up with.
        IPv4 tem_ip = new IPv4();
        tem_ip.setSourceAddress("224.0.0.9");
        int tem_ipaddr = tem_ip.getSourceAddress();

        // Check if an arriving IP packet has a destination 224.0.0.9
        if (ipPacket.getDestinationAddress() == tem_ipaddr) {
            // Check protocol type of UDP
            if (ipPacket.getProtocol() == IPv4.PROTOCOL_UDP) {
                UDP udp = (UDP)ipPacket.getPayload();
                // Check whether the destination port is 520 (not sure whether we should also check the source port)
                if (udp.getDestinationPort() == UDP.RIP_PORT && udp.getSourcePort() == UDP.RIP_PORT) {
                    // If the packet satisfies all the above criteria, then we identify it as a RIP response ro request
                    RIPv2 riPv2 = (RIPv2)udp.getPayload();

                    /* ************ If it is a RIP request *********** */
                    if (riPv2.getCommand() == RIPv2.COMMAND_REQUEST) {

                        // create a new etherPacket to response the request
                        Ethernet response_etherPacket = new Ethernet();
                        // set the type as IPv4
                        response_etherPacket.setEtherType(Ethernet.TYPE_IPv4);
                        // set the response packet's source MAC as the MAC of the interface which previously received etherPacket
                        response_etherPacket.setSourceMACAddress(inIface.getMacAddress().toString());
                        // set the response packet's destination MAC of the source MAC of the previously received etherPacket
                        response_etherPacket.setDestinationMACAddress(etherPacket.getSourceMACAddress());

                        // create a new IPv4 packet to response the request
                        IPv4 response_ipv4 = new IPv4();
                        // set the protocol as UDP
                        response_ipv4.setProtocol(IPv4.PROTOCOL_UDP);
                        // set the response packet's source IP as the IP of the interface which previously received etherPacket
                        response_ipv4.setSourceAddress(inIface.getIpAddress());
                        // set the response packet's destination IP as the source IP of the previously received ipPacket
                        response_ipv4.setDestinationAddress(ipPacket.getSourceAddress());

                        // initialize a new rip and udp to send the response
                        RIPv2 response_rip = new RIPv2();
                        UDP response_udp = new UDP();
                        response_udp.setSourcePort(UDP.RIP_PORT);
                        response_udp.setDestinationPort(UDP.RIP_PORT);
                        response_rip.setCommand(RIPv2.COMMAND_RESPONSE);

                        // initialize to return the current Routetable entries
                        List<RouteEntry> entries = this.routeTable.getEntries();
                        synchronized (entries) {
                            for (RouteEntry e : entries) {
                                // create RIPv2 entries based on the information of the current RouteTable
                                RIPv2Entry riPv2Entry = new RIPv2Entry(e.getDestinationAddress(), e.getMaskAddress(), e.getMetric());
                                // *****************ATTENTION*******************
                                // The following line is the line that I am extremely unsure. I do not know what should I set to the NextHopAddress
                                riPv2Entry.setNextHopAddress(inIface.getIpAddress());
                                // Add each RIPv2 entry to our response RIP structure
                                response_rip.addEntry(riPv2Entry);
                            }
                        }
                        // wrap the response contents layer by layer
                        response_udp.setPayload(response_rip);
                        response_ipv4.setPayload(response_udp);
                        response_etherPacket.setPayload(response_ipv4);

                        // check the check sum
                        response_etherPacket.resetChecksum();
                        response_etherPacket.serialize();

                        // send the packet
                        sendPacket(response_etherPacket, inIface);
                    }

                    /* ************ If it is a RIP response *********** */
                    else {
                       // get all the entries from the received RIP
                       List<RIPv2Entry> rip_entries = riPv2.getEntries();
                       for (RIPv2Entry rip_e : rip_entries) {
                           // for each rip entry, we look up that whether the current RouteTable has the entry information
                           RouteEntry r_e = this.routeTable.lookup(rip_e.getAddress());
                           // if no such IP (or we can say no such entry which is same as the RIP entry)
                           if (r_e == null) {
                               // then we insert these information in the RouteTable
                               routeTable.insert(rip_e.getAddress(), rip_e.getNextHopAddress(), rip_e.getSubnetMask(), inIface, rip_e.getMetric() + 1);
                           }
                           // if the RouteTable has such information then we compare the metric of the route, if we have a smaller value then update it
                           else {
                               if (r_e.getMetric() > rip_e.getMetric() + 1) {
                                   routeTable.update(rip_e.getAddress(), rip_e.getNextHopAddress(), rip_e.getSubnetMask(), inIface, rip_e.getMetric() + 1);
                               }
                           }
                       }
                    }
                }
            }
        }
        
        // Check TTL
        ipPacket.setTtl((byte)(ipPacket.getTtl()-1));
        if (0 == ipPacket.getTtl())
        { return; }
        
        // Reset checksum now that TTL is decremented
        ipPacket.resetChecksum();
        
        // Check if packet is destined for one of router's interfaces
        for (Iface iface : this.interfaces.values())
        {
        	if (ipPacket.getDestinationAddress() == iface.getIpAddress())
        	{ return; }
        }
		
        // Do route lookup and forward
        this.forwardIpPacket(etherPacket, inIface);
	}

    private void forwardIpPacket(Ethernet etherPacket, Iface inIface)
    {
        // Make sure it's an IP packet
		if (etherPacket.getEtherType() != Ethernet.TYPE_IPv4)
		{ return; }
        System.out.println("Forward IP packet");
		
		// Get IP header
		IPv4 ipPacket = (IPv4)etherPacket.getPayload();
        int dstAddr = ipPacket.getDestinationAddress();

        // Find matching route table entry 
        RouteEntry bestMatch = this.routeTable.lookup(dstAddr);

        // If no entry matched, do nothing
        if (null == bestMatch)
        { return; }

        // Make sure we don't sent a packet back out the interface it came in
        Iface outIface = bestMatch.getInterface();
        if (outIface == inIface)
        { return; }

        // Set source MAC address in Ethernet header
        etherPacket.setSourceMACAddress(outIface.getMacAddress().toBytes());

        // If no gateway, then nextHop is IP destination
        int nextHop = bestMatch.getGatewayAddress();
        if (0 == nextHop)
        { nextHop = dstAddr; }

        // Set destination MAC address in Ethernet header
        ArpEntry arpEntry = this.arpCache.lookup(nextHop);
        if (null == arpEntry)
        { return; }
        etherPacket.setDestinationMACAddress(arpEntry.getMac().toBytes());
        
        this.sendPacket(etherPacket, outIface);
    }

    public void initialize() {
	    for (Iface iface : this.interfaces.values()) {
	        int subnet_num = iface.getSubnetMask();
	        int ip = iface.getIpAddress();
	        MACAddress mac = iface.getMacAddress();
	        int dest_addr = ip & subnet_num;
	        this.routeTable.insert(dest_addr, dest_addr, subnet_num, iface, 0);

	        //initialize the ip packet we want to send
            IPv4 ip_packet = new IPv4();
            ip_packet.setProtocol(IPv4.PROTOCOL_UDP); //RIPv2 has to use UDP protocol
            ip_packet.setSourceAddress(ip);
            ip_packet.setSourceAddress("224.0.0.9"); //224.0.0.9 is the reserved multicast IP address


            //initialize the Ethernet wrapper
            Ethernet ethernet_packet = new Ethernet();
            ethernet_packet.setEtherType(Ethernet.TYPE_IPv4);
            ethernet_packet.setSourceMACAddress(mac.toString());
            ethernet_packet.setDestinationMACAddress("FF:FF:FF:FF:FF:FF"); //FF:FF:FF:FF:FF:FF is the broadcast MAC address

            //initialize RIPv2
            RIPv2 rip = new RIPv2();
            rip.setCommand(RIPv2.COMMAND_REQUEST);

            //set up UDP fro RIP port protocol
            UDP udp = new UDP();
            udp.setSourcePort(UDP.RIP_PORT);
            udp.setDestinationPort(UDP.RIP_PORT);

            //set UDP protocol in hierarchy
            udp.setPayload(rip);
            ip_packet.setPayload(udp);
            ethernet_packet.setPayload(ip_packet); //wrap IP packet in ethernet packet
            sendPacket(ethernet_packet, iface);
        }
    }
}
