#include "firewall_module.h"

/* Hook Operations Section */
static struct nf_hook_ops ipv4_loacl_out;
static struct nf_hook_ops ipv4_pre_routing;

/* Filter Rules Section */
static struct fw_hook fwh_ipv4_loacl_out;
static struct fw_hook fwh_ipv4_pre_routing;

#ifdef DEBUG_HOOK_POST_ROUTING
	
	static struct nf_hook_ops ipv4_with_others;
	static struct fw_hook fwh_ipv4_with_others;

#endif

static struct fw_hook arr_fw_hooks[HOOKS_NUMBER];

/* Packet Info */
/**
 * Description: Fetch packet protocol
 *
 * Parameters:
 *		pHeaderIPv4	-	Pointer to IPv4 Protocol header
 *
 * Return value: 
 *		prot_t		-	Protocol of packet
 *
 */
prot_t fetch_packet_protocol(struct iphdr* pHeaderIPv4)
{
	/* Code Section */
	switch (pHeaderIPv4->protocol)
	{
		case PROT_ICMP:
		case PROT_TCP:
		case PROT_UDP:
		case PROT_ANY:
		{
			return (prot_t)pHeaderIPv4->protocol;
		}
		default:
		{
			return PROT_OTHER;
		}
	}
}

/*
 * Inspired by: https://stackoverflow.com/questions/34480548/netfilterhook-displaly-interface-name
 */
/**
 * Description: Fetch packet direction
 *
 * Parameters:
 *		in			-	Pointer to in net device
 *		out			-	Pointer to out net device
 *
 * Return value: 
 *		direction_t	-	Direction of packet
 *
 */
direction_t fetch_packet_direction(const struct net_device *in,
                                   const struct net_device *out)
{
	/* Variable Definition */
	direction_t direction = DIRECTION_ANY;

	/* Code Section */
	/* If out network device exists */
	if (out)
	{
		/* Packet out net dev is IN -> direction in */
		if (!strcmp(out->name, IN_NET_DEVICE_NAME))
		{
			return DIRECTION_IN;
		}
		/* Packet out net dev is OUT -> direction out */
		else if (!strcmp(out->name, OUT_NET_DEVICE_NAME))
		{
			return DIRECTION_OUT;
		}
	}
	/* Else if, in network device  exists */
	else if (in)
	{
		/* Packet in net dev is IN -> direction out */
		if (!strcmp(in->name, IN_NET_DEVICE_NAME))
		{
			return DIRECTION_OUT;
		}
		/* Packet in net dev is OUT -> direction in */
		else if (!strcmp(in->name, OUT_NET_DEVICE_NAME))
		{
			return DIRECTION_IN;
		}
	}

	/* Return value */
	return direction;
}

/*
 * Fetching packet info
 * 
 */
/**
 * Description: Fetch packet information, according to fw_packet_info structure
 *
 * Parameters:
 *		hooknum				-	Hook number
 *		skb					-	Pointer to packet
 *		in					-	Pointer to in net device
 *		out					-	Pointer to out net device
 * 		netfilter_direction	- 	Netfilter direction; is incoming or outgoing packet
 *
 * Return value: 
 *		fw_packet_info		-	Pointer to packet information
 *
 */
fw_packet_info* fetch_packet_info(unsigned int hooknum,
                                  struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out,
								  netfilter_direction_t	   netfilter_direction)
{
	/* Struct Definition */
	struct iphdr* 			pHeaderIPv4;
	struct tcphdr* 			pHeaderTCP;
	struct udphdr* 			pHeaderUDP;
	struct fw_packet_info* 	pPacketInfo;
	struct timeval 			time;

	/* Code Section */
	/* Getting timestamp as early as possible */
	do_gettimeofday(&time);

	/* Allocating packet info */
	pPacketInfo = (fw_packet_info*)kcalloc(1, sizeof(fw_packet_info), GFP_ATOMIC);

	/* Validating allocated successfully */
	if (!pPacketInfo)
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR MEMORY_ALLOCATION_FAILED_MSG);
		#endif

		/* Returning null */
		return pPacketInfo;
	}

	/* Setting time stamp - seconds from Epoch time */
	pPacketInfo->timestamp = time.tv_sec;

	/* Setting hooknum */
	pPacketInfo->hooknum = hooknum;

	/* Setting direction */
	pPacketInfo->direction = fetch_packet_direction(in, out);

	/* Setting packet netfiler direction */
	pPacketInfo->netfilter_direction = netfilter_direction;

	/* If faulty non IPv4 packet */
	if ((!skb) || 
		(!(pHeaderIPv4 = ip_hdr(skb))))
	{
		/* Initializing with default values */
		pPacketInfo->protocol = PROT_ANY;
		pPacketInfo->src_ip = 0;
		pPacketInfo->dst_ip = 0;
		pPacketInfo->src_port = PORT_ANY;
		pPacketInfo->dst_port = PORT_ANY;
		pPacketInfo->ack = ACK_ANY;		

		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR PACKET_INFO_FETCHED_UNRECOGNIZE);
		#endif
	}
	/* Else, initializing according to packet's headers */
	else
	{
		/* Setting protocol */
		pPacketInfo->protocol = fetch_packet_protocol(pHeaderIPv4);

		/* Setting source IP - converting network to host endianity */
		pPacketInfo->src_ip = ntohl(pHeaderIPv4->saddr);

		/* Setting destination IP - converting network to host endianity */
		pPacketInfo->dst_ip = ntohl(pHeaderIPv4->daddr);

		/* Fetching port and ack according to protocol */
		switch (pPacketInfo->protocol)
		{
			case PROT_TCP:
			{
				/* Fetch TCP header */
				pHeaderTCP = (struct tcphdr *)((__u32 *)pHeaderIPv4 + pHeaderIPv4->ihl);

				/* Setting source port - converting network to host endianity */
				pPacketInfo->src_port = ntohs(pHeaderTCP->source);

				/* Setting destination port - converting network to host endianity */
				pPacketInfo->dst_port = ntohs(pHeaderTCP->dest);

				/* Setting ack */
				pPacketInfo->ack = (1 == pHeaderTCP->ack) ? ACK_YES : ACK_NO;

				break;
			}
			case PROT_UDP:
			{
				/* Fetch UDP header */
				pHeaderUDP = (struct udphdr*)(skb->data + (pHeaderIPv4->ihl<<2));

				/* Setting source port - converting network to host endianity */
				pPacketInfo->src_port = ntohs(pHeaderUDP->source);

				/* Setting destination port - converting network to host endianity */
				pPacketInfo->dst_port = ntohs(pHeaderUDP->dest);

				/* Setting ack to default */
				pPacketInfo->ack = ACK_ANY;
				
				break;
			}
		}

		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO PACKET_INFO_FRMT, 
				pPacketInfo->protocol, 
				pPacketInfo->src_ip, 
				pPacketInfo->src_port,
				pPacketInfo->dst_ip,
				pPacketInfo->dst_port);
		#endif

		#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
			printk(KERN_INFO PACKET_INFO_FETCHED_SUCCESSFULLY);
		#endif
	}
	
	/* Verdict to be decided later */
	pPacketInfo->action = DEFAULT_PACKET_ACTION_POLICY;

	/* Reason to be decided */
	pPacketInfo->reason = REASON_ABSENT;

	/* Return packet verdict */
	return pPacketInfo;
}

#ifdef DEBUG_HOOK_POST_ROUTING

/**
 * Description: Postrouting handler of packet, mainly for debug proposes
 *
 * Parameters:
 *		hooknum		-	Hook number
 *		skb			-	Pointer to packet
 *		in			-	Pointer to in net device
 *		out			-	Pointer to out net device
 * 		okfn		- 	Not in use
 *
 * Return value: 
 *		NF_ACCEPT	-	Allow packet, this function is just for debug
 *
 */
unsigned int packet_post_routing_handler(unsigned int hooknum,
                                    	 struct sk_buff *skb,
                                      	 const struct net_device *in,
                                    	 const struct net_device *out,
                                    	 int(*okfn)(struct sk_buff*))
{
    /* Variable Section */	
	fw_packet_info* 	pPacketInfo;   

    /* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_POST_HDR);		
	#endif
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO PACKET_HANDLER_FRMT, hooknum);
	#endif

	/* Fetching packet information */
	pPacketInfo = fetch_packet_info(hooknum, skb, in, out, OUTPUT_PACKET);

	/* Log packet */
	logPacket(pPacketInfo);

	/* Free logged packet info */
	kfree(pPacketInfo);

    /* Return packet verdict */
    return NF_ACCEPT;
}

#endif

/**
 * Description: Checks if it's Christmes packet
 * 				TCP packet with URG && PSH && FIN flags on
 *
 * Parameters:
 *		skb			-	Pointer to packet
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether it's a Christmes packet
 *
 */
BOOL isChristmasTreePacket(struct sk_buff* skb)
{
	/* Struct Definition */
	struct iphdr* 			pHeaderIPv4;
	struct tcphdr*			pHeaderTCP;

	/* Variable Section */
    BOOL bIsChristmasTreePacket = FALSE;  

    /* Code Section */	
	/* If faulty non IPv4 packet */
	if ((!skb) || 
		(!(pHeaderIPv4 = ip_hdr(skb))))
	{
		return FALSE;
	}

	/* Validating TCP protocol */
	if (PROT_TCP == pHeaderIPv4->protocol)
	{
		/* Fetch TCP header */
		if (!(pHeaderTCP = (struct tcphdr *)((__u32 *)pHeaderIPv4 + pHeaderIPv4->ihl)))
		{
			return FALSE;
		}

		/* Validating [ PSH, URG, FIN ] flags are on */
		return (((pHeaderTCP->psh) &&
				 (pHeaderTCP->urg) &&
				 (pHeaderTCP->fin)) ? 
				TRUE : 
				FALSE);
	}

	/* Return value */
	return bIsChristmasTreePacket;
}

/**
 * Description: Checks if packet is from well-known source port and should be sent to firewall proxy
 *
 * Parameters:
 *		port		-	Port number
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from well-known source port and should be sent to firewall proxy
 *
 */
BOOL isForFirewallFromClientPort(__be16 port)
{
	/* Code Section */
	/* Handlign according to port number */
	switch (port)
	{
		/* If it's FTP_DATA port */
		case PORT_FTP_DATA:							
		{
			/* Return true */
			return TRUE;
		}
		/* Default case, it's not */
		default:
		{
			/* Return false */
			return FALSE;
		}
	}

	/* Return false */
	return FALSE;
}

/**
 * Description: Checks if packet is directd to well-known destination port and should be sent to firewall proxy
 *
 * Parameters:
 *		port		-	Port number
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from well-known destination port and should be sent to firewall proxy
 *
 */
BOOL isForFirewallStatefulInspectionPort(__be16 port)
{
	/* Code Section */
	/* Handlign according to port number */
	switch (port)
	{
		/* If packet destination port is HTTP */
		case PORT_HTTP:
		/* If packet destination port is FTP_DATA */
		case PORT_FTP_DATA:		
		/* If packet destination port is FTP_COMMAND */
		case PORT_FTP_COMMAND:				
		/* If packet destination port is SMTP */
		case PORT_SMTP:
		{
			/* Return true */
			return TRUE;
		}
		/* Default case, it's not */
		default:
		{
			/* Return false */
			return FALSE;
		}
	}

	/* Return false */
	return FALSE;
}

/**
 * Description: Checks if packet should be sent to firewall proxy
 * 				Checking according to well-known source and destination ports
 *
 * Parameters:
 *		port		-	pPacketInfo
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet should be sent to firewall proxy
 *
 */
BOOL isForFirewallStatefulInspection(fw_packet_info* pPacketInfo)
{
	/* Code Section */
	/* Checking according to well-known source and destination ports */
	return isForFirewallStatefulInspectionPort(pPacketInfo->src_port) ||
		   isForFirewallStatefulInspectionPort(pPacketInfo->dst_port);
}

/**
 * Description: Checks if packet is from proxy, pretending to be initiator, according to port number
 *
 * Parameters:
 *		port		-	Packet port number
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from proxy, pretending to be initiator
 *
 */
BOOL isFromProxyToInitiatorPort(__be16 port)
{
	/* Code Section */
	/* Handling according to port */
	switch (port)
	{
		/* In case it's FTP_DATA port */
		case PORT_FTP_DATA:
		{
			/* Return true */
			return TRUE;
		}
	}

	/* Deducing FIREWALL_PORT_IN from port, to compare to well-known port numbers */
	port -= FIREWALL_PORT_IN;

	/* Handling according to port */
	switch (port)
	{
		/* In case it's PORT_HTTP port */
		case PORT_HTTP:
		/* In case it's PORT_FTP_DATA port */
		case PORT_FTP_DATA:
		/* In case it's PORT_FTP_COMMAND port */
		case PORT_FTP_COMMAND:
		/* If packet destination port is SMTP */
		case PORT_SMTP:
		{
			/* Return true */
			return TRUE;
		}
		/* Default case, it's not */
		default:
		{
			/* Return false */
			return FALSE;
		}
	}

	/* Return false */
	return FALSE;
}

/**
 * Description: Checks if packet is from proxy, pretending to be initiator
 *
 * Parameters:
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from proxy, pretending to be initiator
 *
 */
BOOL isFromProxyToInitiator(fw_packet_info* pPacketInfo)
{
	/* Code Section */
	/* Checks if packet is from proxy, pretending to be initiator, according to port number */
	return isFromProxyToInitiatorPort(pPacketInfo->src_port);
}

/**
 * Description: Checks if packet is from proxy, pretending to be responder, according to port number
 *
 * Parameters:
 *		port		-	Packet port number
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from proxy, pretending to be responder
 *
 */
BOOL isFromProxyToResponderPort(__be16 port)
{
	/* Code Section */	
	switch (port)
	{
		case PORT_HTTP:	
		case PORT_FTP_DATA:	
		case PORT_FTP_COMMAND:
		case PORT_SMTP:
		{
			return TRUE;
		}
		default:
		{
			return FALSE;
		}
	}

	return FALSE;
}

/**
 * Description: Checks if packet is from proxy, pretending to be responder
 *
 * Parameters:
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from proxy, pretending to be responder
 *
 */
BOOL isFromProxyToResponder(fw_packet_info* pPacketInfo)
{
	/* Code Section */
	/* Checks if packet is from proxy, pretending to be responder, according to port number */
	return isFromProxyToResponderPort(pPacketInfo->dst_port);
}

/**
 * Description: Checks if packet is from proxy, whether as initiator or responder
 *
 * Parameters:
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is from proxy, whether as initiator or responder
 *
 */
BOOL isFromFirewallStatefulInspection(fw_packet_info* pPacketInfo)
{
	/* Code Section */
	/* Checks if packet is from proxy, whether as initiator or responder */
	return  isFromProxyToInitiatorPort(pPacketInfo->src_port) || 
			isFromProxyToResponderPort(pPacketInfo->dst_port);
}

/**
 * Description: Changing packet so it will be directed to firewall proxy
 *
 * Parameters:
 *		skb			-	Pointer to packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: None
 *
 */
void manipulatePacketToStatefulInspection(struct sk_buff* 		skb,
										  fw_packet_info*   	pPacketInfo)
{
	/* Variable Section */	
	int 			tcplen;
	struct iphdr* 	ip_header;
	struct tcphdr*	tcp_header;

	/* Code Section */
	if (!skb)
	{
		return;
	}

	if(skb_is_nonlinear(skb))
    {
        if (skb_linearize(skb))
		{
			return;
		}
    }

	ip_header = (struct iphdr *)skb_network_header(skb);

	if (!ip_header)
	{
		return;
	}

	if (PROT_TCP != ip_header->protocol) //non TCP packet
	{
		return;
	}

	//for incoming packets use +20
	// tcp_header = (struct tcphdr *)(skb_transport_header(skb)+20); 
	tcp_header = ((struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4))); 
	// tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);

	if (!tcp_header)
	{
		return;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_TO_STATEFUL_FIREWALL_INSPECTION, ntohl(ip_header->daddr), ntohs(tcp_header->dest));
	#endif
		
	//changing of routing
	/* Chaning packet routing to proxy according to it's original direction */
	switch (pPacketInfo->direction)
	{
		/* In case of direction out */
		case DIRECTION_OUT:
		{
			//change to yours IP
			ip_header->daddr = htonl(FIREWALL_IP2);
			
			/* End of case */
			break;
		}
		/* In case of direction in */
		case DIRECTION_IN:
		{
			/* If from client port, i.e. FTP data port */
			if (isForFirewallFromClientPort(ntohs(tcp_header->source)) ||
				isForFirewallFromClientPort(ntohs(tcp_header->dest)))
			{
				//change to yours IP
				ip_header->daddr = htonl(FIREWALL_IP1);
			}
			/* Else, for firewall proxy */
			else
			{
				//change to yours IP
				ip_header->daddr = htonl(FIREWALL_IP1);
				//change to yours listening port			
				tcp_header->dest = htons(FIREWALL_PORT_IN) + tcp_header->dest;
			}

			/* End of case */
			break;
		}
		/* Default case, invalid direction */
		default:
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_INFO PACKET_MANIPULATION_TO_FIREWALL_FAILED_FRMT, PACKET_DIRECTION_ILLEGAL);
			#endif

			/* End of case */
			return;
		}
	}
		
	//here start the fix of checksum for both IP and TCP
	tcplen = (skb->len - ((ip_header->ihl ) << 2));
	tcp_header->check=0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FIREWALL_IN_PACKET_DETAILS_FRMT, 
			   pPacketInfo->protocol, 
			   ntohl(ip_header->saddr), 
			   ntohs(tcp_header->source),
			   ntohl(ip_header->daddr),
			   ntohs(tcp_header->dest));
	#endif
}

/**
 * Description: Changing packet so it will be directed to other peer
 * 				i.e. 
 * 					If sender 		-> 	src is connection row sender
 *					If responder 	-> 	src is connection row responder
 * 
 * Parameters:
 *		skb				-	Pointer to packet
 *		trSenderRole	-	Sender role
 *		pPacketInfo		-	Pointer to packet info
 *		pcConnectionRow	-	Pointer to packet connection row
 *
 * Return value: None
 *
 */
void manipulatePacketToOtherPeer(struct sk_buff* 	skb,
								 connection_role_t  trSenderRole,
								 fw_packet_info*	pPacketInfo,
								 connection_row_t*	pcConnectionRow)
{
	/* Variable Section */
	int 			tcplen;
	struct iphdr* 	ip_header;
	struct tcphdr*	tcp_header;

	/* Code Section */
	if (!skb)
	{
		return;
	}

	if(skb_is_nonlinear(skb))
    {
        if (skb_linearize(skb))
		{
			return;
		}
    }

	ip_header = (struct iphdr *)skb_network_header(skb);

	if (!ip_header)
	{
		return;
	}

	if (PROT_TCP != ip_header->protocol) //non TCP packet
	{
		return;
	}

	//for incoming packets use +20
	tcp_header = ((struct tcphdr*)((char*)ip_header + (ip_header->ihl * 4))); 	

	if (!tcp_header)
	{
		return;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_FROM_STATEFUL_FIREWALL_INSPECTION, ntohl(ip_header->saddr), ntohs(tcp_header->source));
	#endif

	/* Handling according to senders role */
	switch (trSenderRole)
	{
		/* In case sender is initiator */
		case CONNECTION_INITIATOR:		
		{
			//change to yours IP
			ip_header->saddr = htonl(pcConnectionRow->initiator_ip);
			//change to yours listening port
			tcp_header->source = htons(pcConnectionRow->initiator_port);
			/* End of case */
			break;
		}
		/* In case sender is responder */
		case CONNECTION_RESPONDER:
		{
			//change to yours IP
			ip_header->saddr = htonl(pcConnectionRow->responder_ip);
			//change to yours listening port
			tcp_header->source = htons(pcConnectionRow->responder_port);
			/* End of case */
			break;
		}
		/* Default case, invalid role */
		default:
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_INFO PACKET_MANIPULATION_TO_FIREWALL_FAILED_FRMT, PACKET_DIRECTION_ILLEGAL);
			#endif

			return;
		}
	}

	//here start the fix of checksum for both IP and TCP
	tcplen = (skb->len - ((ip_header->ihl )<< 2));
	tcp_header->check=0;
	tcp_header->check = tcp_v4_check(tcplen, ip_header->saddr, ip_header->daddr,csum_partial((char*)tcp_header, tcplen,0));
	skb->ip_summed = CHECKSUM_NONE; //stop offloading
	ip_header->check = 0;
	ip_header->check = ip_fast_csum((u8 *)ip_header, ip_header->ihl);

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FIREWALL_OUT_PACKET_DETAILS_FRMT, 
			   pPacketInfo->protocol, 
			   ntohl(ip_header->saddr), 
			   ntohs(tcp_header->source),
			   ntohl(ip_header->daddr),
			   ntohs(tcp_header->dest));
	#endif
}

/* Packet Handlers */
/**
 * Description: Prerouting handler of packet
 * 				Checking if it's christmes packet
 * 				Checking if rules approve packet, if it's a new conncection
 * 				Checking if it's part of an existing connection, if so - updating states according to FSM
 * 				Handling packet according to verdict and logging it
 *
 * Parameters:
 *		hooknum		-	Hook number
 *		skb			-	Pointer to packet
 *		in			-	Pointer to in net device
 *		out			-	Pointer to out net device
 * 		okfn		- 	Not in use
 *
 * Return value: 
 *		NF_ACCEPT	-	If packet should be allowed
 *		NF_BLOCK	-	If packet should be blocked
 *
 */
unsigned int packet_pre_routing_handler(unsigned int hooknum,
                                    	struct sk_buff *skb,
                                    	const struct net_device *in,
                                    	const struct net_device *out,
                                    	int(*okfn)(struct sk_buff*))
{
    /* Variable Section */
	verdict_t			vVerdict;
	fw_packet_info* 	pPacketInfo;
	connection_row_t*	pcConnectionRow	=	NULL;

    /* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_INCOMING_HDR);		
	#endif
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO PACKET_HANDLER_FRMT, hooknum);
	#endif

	/* Fetching packet information */
	pPacketInfo = fetch_packet_info(hooknum, skb, in, out, INPUT_PACKET);

	/* If not alloacted - no more memory to log either, dropping */
	if (!pPacketInfo)
	{
		/* Dropping packet */
		return NF_DROP;
	}

	/* If christmas tree packet - dropping */
	if (isChristmasTreePacket(skb))
	{ 
		pPacketInfo->action = NF_DROP;
		pPacketInfo->reason = REASON_XMAS_PACKET;
	}
	/* Else, setting packet verdict */
	else
	{
		/* If packet verdict should be set according to connection table */
		if (isConnectionTableVerdict(skb, pPacketInfo))
		{
			/* Set packet verdict according to connection table */
			setIncomingPacketVerdictByConnectionTable(skb, pPacketInfo, &pcConnectionRow);
		}
		/* Else, setting packet verdict according to rules */
		else
		{
			/* Setting packet verdict according to rules */
			setPacketVerdictByRules(pPacketInfo);

			/* Add packet to connection table if needed */			
			addPacketToConnectionTableIfNeeded(skb, pPacketInfo, &pcConnectionRow);
		}
	}

	/* If packet is legal */
	if (VERDICT_ALLOW == pPacketInfo->action)
	{
		/* If packet should be sent to firewall stateful inspection */
		if (isForFirewallStatefulInspection(pPacketInfo))
		{
			/* If connection row is null - therefore connection already exists */
			if (pcConnectionRow)
			{
				/* Manipulatin packet to get to stateful inspection in proxy */
				manipulatePacketToStatefulInspection(skb, pPacketInfo);
			}
		}
	}

	/* Setting verdict in return value */
	vVerdict = pPacketInfo->action;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_VERDICT_FRMT, pPacketInfo->action, pPacketInfo->reason);
	#endif

	/* Log packet */
	logPacket(pPacketInfo);

	/* Free logged packet info */
	kfree(pPacketInfo);

    /* Return packet verdict */
    return vVerdict;
}

/**
 * Description: Local-out handler of packet
 * 				Checking if from firewall proxy, and manipulating packet to other peer
 *
 * Parameters:
 *		hooknum		-	Hook number
 *		skb			-	Pointer to packet
 *		in			-	Pointer to in net device
 *		out			-	Pointer to out net device
 * 		okfn		- 	Not in use
 *
 * Return value: 
 *		NF_ACCEPT	-	If packet should be allowed
 *		NF_BLOCK	-	If packet should be blocked
 *
 */
unsigned int packet_local_out_handler(unsigned int hooknum,
                                      struct sk_buff *skb,
                                      const struct net_device *in,
                                      const struct net_device *out,
                                      int(*okfn)(struct sk_buff*))
{
	/* Variable Section */
	fw_packet_info* 	pPacketInfo;
	connection_role_t   trSenderRole;
	verdict_t			vVerdict		= 	VERDICT_ALLOW;
	connection_row_t*	pcConnectionRow	=	NULL;

    /* Code Section */
	#ifdef DEBUG_PASS_NO_PRINT_LOCALHOST

		struct iphdr* 			pHeaderIPv4;

		if ((skb) && 
			((pHeaderIPv4 = ip_hdr(skb))))
		{
			/* If localhost communication - just pass it */
			if ((LOCALHOST_IP == ntohl(pHeaderIPv4->saddr)) ||
				(LOCALHOST_IP == ntohl(pHeaderIPv4->daddr)))
			{
				return vVerdict;
			}
		}
	
	#endif

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_OUTGOING_HDR);
	#endif
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO PACKET_HANDLER_FRMT, hooknum);
	#endif

	/* Fetching packet information */
	pPacketInfo = fetch_packet_info(hooknum, skb, in, out, OUTPUT_PACKET);

	/* If not alloacted - no more memory to log either, dropping */
	if (!pPacketInfo)
	{
		/* Dropping packet */
		return NF_DROP;
	}

	/* If firewall is inactive */
	if (!isFirewallActive())
	{
		pPacketInfo->action = VERDICT_ALLOW;
		pPacketInfo->reason = REASON_FW_INACTIVE;
	}
	/* Else, validate packet from stateful inspection */
	else
	{
		/* If for stateful inspection */
		if (isFromFirewallStatefulInspection(pPacketInfo))
		{
			/* Set packet verdict according to connection table */
			setOutgoingPacketVerdictByConnectionTable(skb, pPacketInfo, &trSenderRole, &pcConnectionRow);
			
			/* Manipulatin packet to get to other peer */
			manipulatePacketToOtherPeer(skb, trSenderRole, pPacketInfo, pcConnectionRow);
		}
	}

	#if DEFAULT_ALLOW_OUTER_PACKETS
		pPacketInfo->action = VERDICT_ALLOW;
		pPacketInfo->reason = REASON_OUTER_PACKET;
	#endif

	/* Setting verdict in return value */
	vVerdict = pPacketInfo->action;

	#if LOG_OUTER_PACKETS
		/* Log packet */
		logPacket(pPacketInfo);
	#endif

	/* Free packet info */
	kfree(pPacketInfo);

    /* Return packet verdict */
    return vVerdict;
}

/* Register & Unregister Hooks */
/**
 * Description: Register hook to netfilter
 *
 * Parameters:
 *		pnfho 		-	A pointer to hook operation to register by netfilter
 *		okfn		-	A pointer to an "okay function" that will deal with the packet
 *						if all the hooks on that point will return ACCEPT
 *		pf			-	The protocol family
 *		hooknum		-	The hooknum (the place that the function was called from)
 *		priority	-	More than one hook callback can be registered on the same hook. 
 *						Hook callbacks with lower priorities are called first
 *
 * Return value: 
 *		DEV_SUCCESS				-	For success
 *		HOOK_REGISTERING_FAILED	-	If hook registering has failed
 *
 */
static EDevReturnValue register_hook(struct nf_hook_ops* pnfho, nf_hookfn* okfn, int pf, int hooknum, int priority)
{
	/* Setting fields of hook operation according to parameters */
	pnfho->hook = okfn;
	pnfho->pf = pf;
	pnfho->hooknum = hooknum;
	pnfho->priority = priority;

	/* Registering initialized hook operation, checking for negative return code */
	if (0 > nf_register_hook(pnfho))
	{
		return HOOK_REGISTERING_FAILED;
	}

	return DEV_SUCCESS;
}

/**
 * Description: Unregister a given amount of hooks from netfilter
 * 				order of unregistration if from last to first 
 *				which is opposite from registration order for successful roll-back
 *
 * Parameters:
 *		arr_fw_rules	-	The array of hook rules of which are to unregister
 *		amount			-	The amount of hook rules to unregister in reverse order
 *
 * Return value: None
 *
 */
static void unregister_hooks(struct fw_hook arr_fw_rules[], int amount)
{
    /* Variable Section */
	struct fw_hook fwhHook;
	int unregister_rule_index;

    /* Code Section */
	/* Going over filter rules and unregister them in reverse order */
	for (unregister_rule_index = amount - 1; 0 <= unregister_rule_index; --unregister_rule_index)
	{
		fwhHook = arr_fw_rules[unregister_rule_index];

		nf_unregister_hook(fwhHook.pnfho);
	}
}

/**
 * Description: Register hooks to netfilter
 *
 * Parameters: None
 *
 * Return value: 
 *		DEV_SUCCESS			    -	For success
 *		HOOK_REGISTERING_FAILED	-	If hook registering has failed
 *
 */
static EDevReturnValue register_hooks(struct fw_hook arr_fw_rules[],
                                      int amount)
{
    /* Variable Definition */
    struct fw_hook fwhHook;
	int register_rule_index;
	EDevReturnValue result;

    /* Code Section */
	result = DEV_SUCCESS;

	/* Going over filter rules and register them */
	for (register_rule_index = 0; amount > register_rule_index; ++register_rule_index)
	{
		fwhHook = arr_fw_rules[register_rule_index];

		/* Register current rule */
		if ((result = 
                register_hook(fwhHook.pnfho, 
                              fwhHook.handler, 
                              fwhHook.pf, 
                              fwhHook.hooknum, 
                              NF_IP_PRI_FIRST)))
		{
			/* Registration failed, so unregistering all past-registered rules */
			unregister_hooks(arr_fw_rules, register_rule_index);

			return result;
		}
	}

	return result;
}

/**
 * Description: FireWall initialization of hooks varaibles function
 *				Initializing firewall hooks
 *				Initializing firewall hooks array
 *
 * Parameters: None
 *
 * Return value: None
 *
 */
static void initializeHookVariables(void)
{
	fwh_ipv4_pre_routing.pnfho 					= &ipv4_pre_routing;
	fwh_ipv4_pre_routing.pf 					= PF_INET;
	fwh_ipv4_pre_routing.hooknum 				= NF_INET_PRE_ROUTING;
    fwh_ipv4_pre_routing.handler 				= packet_pre_routing_handler;

	fwh_ipv4_loacl_out.pnfho 					= &ipv4_loacl_out;
	fwh_ipv4_loacl_out.pf 						= PF_INET;
	fwh_ipv4_loacl_out.hooknum 					= NF_INET_LOCAL_OUT;
    fwh_ipv4_loacl_out.handler 					= packet_local_out_handler;

	#ifdef DEBUG_HOOK_POST_ROUTING
		fwh_ipv4_with_others.pnfho = &ipv4_with_others;
		fwh_ipv4_with_others.pf = PF_INET;
		fwh_ipv4_with_others.hooknum = NF_INET_POST_ROUTING; 
		fwh_ipv4_with_others.handler = packet_post_routing_handler;
		arr_fw_hooks[HOOK_WITH_OTHERS_DEBUG] = fwh_ipv4_with_others;	
	#endif
	
	arr_fw_hooks[HOOK_IPV4_PRE_ROUTING_INDEX] 	= fwh_ipv4_pre_routing;
	arr_fw_hooks[HOOK_IPV4_LOCAL_OUT_INDEX] 	= fwh_ipv4_loacl_out;	
}

/**
 * Description: Registering hooks
 *
 * Parameters: None
 *
 * Return value:
 *		DEV_SUCCESS				-	For success
 *		HOOK_REGISTERING_FAILED	-	If hook registering has failed
 */
EDevReturnValue registerHooks(void) 
{
    /* Variable Section */
	EDevReturnValue result;

    /* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO REGISTER_HOOKES_BEGIN);
	#endif

	result = DEV_SUCCESS;  

    /* Initialize hook varaibles */ 
    initializeHookVariables();

	/* Register hooks */	
	if ((result = register_hooks(arr_fw_hooks, HOOKS_NUMBER)))
	{
		return result;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO REGISTER_HOOKES_ENDED);
	#endif

	return result;
}

/**
 * Description: Unregistering all hooks
 *
 * Parameters: None
 *
 * Return value: None
 */
void unregisterHooks(void)
{
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO UNREGISTER_HOOKES_BEGIN);
	#endif

	/* Unregister hooks */
	unregister_hooks(arr_fw_hooks, HOOKS_NUMBER);

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO UNREGISTER_HOOKES_ENDED);
	#endif
}
