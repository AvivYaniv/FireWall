#include "firewall_module.h"

/* Hook Operations Section */
static struct nf_hook_ops ipv6_with_any;

static struct nf_hook_ops ipv4_with_others;
static struct nf_hook_ops ipv4_to_firewall;
static struct nf_hook_ops ipv4_from_firewall;

/* Filter Rules Section */
static struct fw_hook fwh_ipv6_with_any;
static struct fw_hook fwh_ipv4_with_others;
static struct fw_hook fwh_ipv4_to_firewall;
static struct fw_hook fwh_ipv4_from_firewall;

static struct fw_hook arr_fw_hooks[HOOKS_NUMBER];

/* Packet Info */
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

fw_packet_info* fetch_packet_info(unsigned int hooknum,
                                  struct sk_buff *skb,
                                  const struct net_device *in,
                                  const struct net_device *out)
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

		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO PACKET_INFO_FETCHED_FRMT, pPacketInfo->protocol, pPacketInfo->src_ip, pPacketInfo->dst_ip);
		#endif

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

BOOL isChristmasTreePacket(struct sk_buff *skb)
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

/* Packet Handlers */
unsigned int packet_forward_handler(unsigned int hooknum,
                                    struct sk_buff *skb,
                                    const struct net_device *in,
                                    const struct net_device *out,
                                    int(*okfn)(struct sk_buff*))
{
    /* Variable Section */
	verdict_t			vVerdict;
	fw_packet_info* 	pPacketInfo;   


    /* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_HANDLER_FRMT, hooknum);
	#endif

	/* Fetching packet information */
	pPacketInfo = fetch_packet_info(hooknum, skb, in, out);

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
	/* Else, setting packet verdict according to rules */
	else
	{
		/* Setting packet verdict according to rules */
		setPacketVerdict(pPacketInfo);
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
	fwh_ipv6_with_any.pnfho = &ipv6_with_any;
	fwh_ipv6_with_any.pf = PF_INET6;
	fwh_ipv6_with_any.hooknum = NF_INET_PRE_ROUTING;
    fwh_ipv6_with_any.handler = NULL;

	fwh_ipv4_with_others.pnfho = &ipv4_with_others;
	fwh_ipv4_with_others.pf = PF_INET;
	fwh_ipv4_with_others.hooknum = NF_INET_FORWARD;
    fwh_ipv4_with_others.handler = packet_forward_handler;

	fwh_ipv4_to_firewall.pnfho = &ipv4_to_firewall;
	fwh_ipv4_to_firewall.pf = PF_INET;
	fwh_ipv4_to_firewall.hooknum = NF_INET_LOCAL_IN;
    fwh_ipv4_to_firewall.handler = NULL;

	fwh_ipv4_from_firewall.pnfho = &ipv4_from_firewall;
	fwh_ipv4_from_firewall.pf = PF_INET;
	fwh_ipv4_from_firewall.hooknum = NF_INET_LOCAL_OUT;
    fwh_ipv4_from_firewall.handler = NULL;
	
	arr_fw_hooks[HOOK_IPV4_WITH_OTHERS_INDEX] = fwh_ipv4_with_others;
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
