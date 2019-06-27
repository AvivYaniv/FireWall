#include <linux/ip.h>
#include <linux/tcp.h>

#include "tcp_connection.h"

/* Array Section */
/* 
 * Based on: RFC 793
 *  https://tools.ietf.org/html/rfc793
 */
/* Client : Initiator */
static tcp_state_transition_t tcp_client_sends_server_transition_table[] = 
    {
        /*      State                               Sends                   Becomes                */
        {       TCP_STATE_CLOSED            ,   TCP_FLAGS_SYN       ,   TCP_STATE_SYN_SENT          },          
        {       TCP_STATE_SYN_SENT          ,   TCP_FLAGS_ACK       ,   TCP_STATE_ESTABLISHED       },  
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK       ,   TCP_STATE_ESTABLISHED       },  
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_FIN       ,   TCP_STATE_FIN_WAIT_1        },  
        {       TCP_STATE_FIN_WAIT_1        ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSING           },  
        {       TCP_STATE_FIN_WAIT_2        ,   TCP_FLAGS_ACK       ,   TCP_STATE_TIME_WAIT         },                 
        {       TCP_STATE_TIME_WAIT         ,   TCP_FLAGS_ACK       ,   TCP_STATE_TIME_WAIT   	    },             
        {       TCP_STATE_CLOSING           ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_CLOSED            }, 
        {       TCP_STATE_CLOSING           ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSED            }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_FINISHED          },  
        {       TCP_STATE_FINISHED          ,   TCP_FLAGS_ACK       ,   TCP_STATE_FINISHED          },      
        {       TCP_STATE_OTHER_FINISHED    ,   TCP_FLAGS_ACK       ,   TCP_STATE_OTHER_FINISHED    },  
        {       TCP_STATE_OTHER_FINISHED    ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_BOTH_FINISHED     },  
        {       TCP_STATE_BOTH_FINISHED     ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSED            },  
    };

static tcp_state_transition_t tcp_client_recives_server_transition_table[] = 
    {
        /*      State                               Recives                 Becomes                 */
        {       TCP_STATE_SYN_SENT          ,   TCP_FLAGS_ACK_SYN   ,   TCP_STATE_ESTABLISHED       }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK       ,   TCP_STATE_ESTABLISHED       },                 
        {       TCP_STATE_FIN_WAIT_1        ,   TCP_FLAGS_ACK       ,   TCP_STATE_FIN_WAIT_2        }, 
        {       TCP_STATE_FIN_WAIT_1        ,   TCP_FLAGS_FIN       ,   TCP_STATE_FIN_WAIT_1        }, 
        {       TCP_STATE_FIN_WAIT_2        ,   TCP_FLAGS_FIN       ,   TCP_STATE_FIN_WAIT_2        }, 
        {       TCP_STATE_CLOSING           ,   TCP_FLAGS_ACK       ,   TCP_STATE_TIME_WAIT         }, 
        {       TCP_STATE_FIN_WAIT_2        ,   TCP_FLAGS_ACK       ,   TCP_STATE_FIN_WAIT_2        },             
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_OTHER_FINISHED    }, 
        {       TCP_STATE_FIN_WAIT_1        ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_OTHER_FINISHED    }, 
        {       TCP_STATE_FIN_WAIT_2        ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_OTHER_FINISHED    },     
        {       TCP_STATE_FINISHED          ,   TCP_FLAGS_ACK       ,   TCP_STATE_FINISHED          }, 
        {       TCP_STATE_FINISHED          ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_BOTH_FINISHED     }, 
        {       TCP_STATE_BOTH_FINISHED     ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSED            }, 
    };

/* Server : Responder */
static tcp_state_transition_t tcp_server_recives_client_transition_table[] = 
    {
        /*      State                               Recives                 Becomes              */
        {       TCP_STATE_LISTEN            ,   TCP_FLAGS_SYN       ,   TCP_STATE_SYN_RECEIVED      }, 
        {       TCP_STATE_SYN_RECEIVED      ,   TCP_FLAGS_ACK       ,   TCP_STATE_ESTABLISHED       }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK       ,   TCP_STATE_ESTABLISHED       }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_FIN       ,   TCP_STATE_CLOSE_WAIT        }, 
        {       TCP_STATE_CLOSE_WAIT        ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSE_WAIT        }, 
        {       TCP_STATE_LAST_ACK          ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSED            }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_OTHER_FINISHED    }, 
        {       TCP_STATE_CLOSE_WAIT        ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_OTHER_FINISHED    }, 
        {       TCP_STATE_LAST_ACK          ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_OTHER_FINISHED    }, 
        {       TCP_STATE_FINISHED          ,   TCP_FLAGS_ACK       ,   TCP_STATE_FINISHED          }, 
        {       TCP_STATE_FINISHED          ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_BOTH_FINISHED     },       
        {       TCP_STATE_BOTH_FINISHED     ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSED            }, 
    };

static tcp_state_transition_t tcp_server_sends_client_transition_table[] = 
    {
        /*      State                               Sends                    Becomes             */  
        {       TCP_STATE_LISTEN            ,   TCP_FLAGS_ACK_SYN   ,   TCP_STATE_SYN_RECEIVED      }, 
        {       TCP_STATE_SYN_RECEIVED      ,   TCP_FLAGS_ACK_SYN   ,   TCP_STATE_ESTABLISHED       }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK       ,   TCP_STATE_ESTABLISHED       }, 
        {       TCP_STATE_CLOSE_WAIT        ,   TCP_FLAGS_FIN       ,   TCP_STATE_LAST_ACK          }, 
        {       TCP_STATE_CLOSE_WAIT        ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSE_WAIT        }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_FIN       ,   TCP_STATE_LAST_ACK          }, 
        {       TCP_STATE_ESTABLISHED       ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_FINISHED          },                 
        {       TCP_STATE_CLOSE_WAIT        ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_FINISHED          },          
        {       TCP_STATE_OTHER_FINISHED    ,   TCP_FLAGS_ACK       ,   TCP_STATE_OTHER_FINISHED    }, 
        {       TCP_STATE_OTHER_FINISHED    ,   TCP_FLAGS_ACK_FIN   ,   TCP_STATE_BOTH_FINISHED     }, 
        {       TCP_STATE_BOTH_FINISHED     ,   TCP_FLAGS_ACK       ,   TCP_STATE_CLOSED            }, 
    };

/* Methods Section */
/**
 * Description: Returns if packet matches an ongiong TCP conversation, ACK flag is on
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet matches an ongiong TCP conversation
 *
 */
BOOL isMiddleOfConnectionTCP(struct sk_buff*	skb,
						     fw_packet_info* 	pPacketInfo)
{
	/* Struct Definition */
	struct iphdr* 			pHeaderIPv4;
	struct tcphdr*			pHeaderTCP;

	/* Variable Section */
    BOOL bIsAckFlagIsSetInTCP = FALSE;  

    /* Code Section */	
	/* If not a TCP packet */
	if (!pPacketInfo || 
		(PROT_TCP != pPacketInfo->protocol))
	{
		return FALSE;
	}

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

		/* Validating [ ACK ] flag is on */
		return ((pHeaderTCP->ack) ? 
				TRUE : 
				FALSE);
	}

	/* Return value */
	return bIsAckFlagIsSetInTCP;
}

/**
 * Description: Returns if packet matches begining of TCP conversation, SYN flag is on
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet matches begining of TCP conversation
 *
 */
BOOL isBeginningOfDataFTPConnection(struct sk_buff*	    skb,
						            fw_packet_info* 	pPacketInfo)
{
	/* Struct Definition */    
	struct iphdr* 			pHeaderIPv4;
	struct tcphdr*			pHeaderTCP;

	/* Variable Section */
    __be16                  sSrcPort    =   0;

    /* Code Section */	
	/* If not a TCP packet */
	if (!pPacketInfo || 
		(PROT_TCP != pPacketInfo->protocol))
	{
		return FALSE;
	}

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

        /* Fetching source port */
        sSrcPort = ntohs(pHeaderTCP->source);

        /* If source port is not FTP_DATA, those should be checked according to connection table */
        if (PORT_FTP_DATA != sSrcPort)
        {
            return FALSE;
        }

		/* Validating [ SYN ] flag is on */
		return ((pHeaderTCP->syn) ? 
				TRUE : 
				FALSE);
	}

	/* Return failure */
	return FALSE;
}

/**
 * Description: If TCP packet verdict should be set according to connection table
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet verdict should be set according to connection table
 *
 */
BOOL isConnectionTableVerdictTCP(struct sk_buff*	skb,
						 	     fw_packet_info* 	pPacketInfo)
{
    return  isMiddleOfConnectionTCP(skb, pPacketInfo)   || 
            isBeginningOfDataFTPConnection(skb, pPacketInfo);
}

/**
 * Description: If packet is the start of TCP conversation, both SYN && ACK flags are on
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether packet is the start of TCP conversation, both SYN && ACK flags are on
 *
 */
BOOL isStartOfConnectionTCP(struct sk_buff*	        skb,
						    fw_packet_info*         pPacketInfo)
{
	/* Struct Definition */
	struct iphdr* 			pHeaderIPv4;
	struct tcphdr*			pHeaderTCP;

	/* Variable Section */
    BOOL bIsAckFlagIsSetInTCP = FALSE;  

    /* Code Section */	
	/* If not a TCP packet */
	if (!pPacketInfo || 
		(PROT_TCP != pPacketInfo->protocol))
	{
		return FALSE;
	}

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

		/* Validating [ ACK ] flag is off and [ SYN ] flag is on */
		return (((!pHeaderTCP->ack) &&
                 (pHeaderTCP->syn))
				? TRUE : FALSE);
	}

	/* Return value */
	return bIsAckFlagIsSetInTCP;
}

/**
 * Description: If should be created a connection row for packet
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether should be created a connection row for packet
 *
 */
BOOL isNeddedAddConnectionTCP(struct sk_buff*           skb,  
                              fw_packet_info*           pPacketInfo)
{
    return isStartOfConnectionTCP(skb, pPacketInfo);
}

/**
 * Description: Adding a new TCP connection to connection table, from outer source i.e. FTP_DATA
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether added successfully
 *
 */
BOOL addNewTCPToConnectionTable(new_connection_raw_t*   pNewConnection)
{
    /* Struct Definition */
    struct timeval 			time;

    /* Variable Definition */
    BOOL                    bIsAdded            = FALSE;
    connection_row_t*       pcConnectionRow     = NULL;
    
    /* Code Section */
	/* Getting timestamp as early as possible */
	do_gettimeofday(&time);

    /* Creating connection row */
    pcConnectionRow = (connection_row_t*)kcalloc(1, sizeof(connection_row_t), GFP_ATOMIC);

    /* Validating allocated successfully */
	if (!pcConnectionRow)
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR MEMORY_ALLOCATION_FAILED_MSG);
		#endif

		/* Returning failure */
		return FALSE;
	}

    /* Setting connection row information */
    pcConnectionRow->initiator_ip           =   pNewConnection->initiator_ip;
    pcConnectionRow->initiator_port         =   pNewConnection->initiator_port;
    pcConnectionRow->responder_ip           =   pNewConnection->responder_ip;
    pcConnectionRow->responder_port         =   pNewConnection->responder_port;
    pcConnectionRow->protocol               =   (connection_protocols_t)pNewConnection->protocol;
    pcConnectionRow->time_added             =   time.tv_sec;

    pcConnectionRow->initiator_state        =   TCP_STATE_CLOSED;
    pcConnectionRow->proxy_responder_state  =   TCP_STATE_LISTEN;

    pcConnectionRow->proxy_initiator_state  =   TCP_STATE_CLOSED;
    pcConnectionRow->responder_state        =   TCP_STATE_LISTEN;      

    /* Setting whether added successfully */        
    bIsAdded = addToConnectionTable(pcConnectionRow);

    /* If not added - freeing */
    if (!bIsAdded)
    {
        /* Free client row */
        kfree(pcConnectionRow);

        /* As a matter of security - setting null */
        pcConnectionRow = NULL;

        /* Return failure */
        return FALSE;
    }  

    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO CONECTION_ROW_ADDED_FRMT, 
                CONNECTION_ROLE_STRING[CONNECTION_INITIATOR], 
                pcConnectionRow->initiator_ip, 
                pcConnectionRow->initiator_port, 
                TCP_STATE_STRING[pcConnectionRow->initiator_state], 
                CONNECTION_ROLE_STRING[CONNECTION_RESPONDER], 
                pcConnectionRow->responder_ip, 
                pcConnectionRow->responder_port, 
                TCP_STATE_STRING[pcConnectionRow->responder_state], 
                pcConnectionRow->protocol, 
                pcConnectionRow->time_added);
    #endif

    /* Return whether both added successfully */
    return bIsAdded;
}

/**
 * Description: Adding a new TCP connection to connection table, as part of regular TCP communication
 *
 * Parameters:
 *		skb			-	The packet
 *		pPacketInfo	-	Pointer to packet info
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether added successfully
 *
 */
BOOL addTCPPacketToConnectionTable(fw_packet_info*      pPacketInfo,
                                   connection_row_t**	ppcConnectionRow)
{
    /* Struct Definition */
    struct timeval 			time;

    /* Variable Definition */
    BOOL                    bIsAdded            = FALSE;
    connection_row_t*       pcConnectionRow     = NULL;
    
    /* Code Section */
	/* Getting timestamp as early as possible */
	do_gettimeofday(&time);

    /* Creating connection row */
    pcConnectionRow = (connection_row_t*)kcalloc(1, sizeof(connection_row_t), GFP_ATOMIC);

    /* Validating allocated successfully */
	if (!pcConnectionRow)
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR MEMORY_ALLOCATION_FAILED_MSG);
		#endif

		/* Returning failure */
		return FALSE;
	}

    /* Setting connection row information */
    pcConnectionRow->initiator_ip           =   pPacketInfo->src_ip;
    pcConnectionRow->initiator_port         =   pPacketInfo->src_port;
    pcConnectionRow->responder_ip           =   pPacketInfo->dst_ip;
    pcConnectionRow->responder_port         =   pPacketInfo->dst_port;
    pcConnectionRow->protocol               =   (connection_protocols_t)pPacketInfo->protocol;
    pcConnectionRow->time_added             =   time.tv_sec;

    pcConnectionRow->initiator_state        =   TCP_STATE_SYN_SENT;
    pcConnectionRow->proxy_responder_state  =   TCP_STATE_LISTEN;

    pcConnectionRow->proxy_initiator_state  =   TCP_STATE_CLOSED;
    pcConnectionRow->responder_state        =   TCP_STATE_LISTEN;   

    /* Setting whether added successfully */        
    bIsAdded = addToConnectionTable(pcConnectionRow);

    /* Setting connection row */
    *ppcConnectionRow = pcConnectionRow;

    /* If not added - freeing */
    if (!bIsAdded)
    {
        /* Free client row */
        kfree(pcConnectionRow);

        /* As a matter of security - setting null */
        pcConnectionRow = NULL;

        /* Return failure */
        return FALSE;
    }  

    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO CONECTION_ROW_ADDED_FRMT, 
                CONNECTION_ROLE_STRING[CONNECTION_INITIATOR], 
                pcConnectionRow->initiator_ip, 
                pcConnectionRow->initiator_port, 
                TCP_STATE_STRING[pcConnectionRow->initiator_state], 
                CONNECTION_ROLE_STRING[CONNECTION_RESPONDER], 
                pcConnectionRow->responder_ip, 
                pcConnectionRow->responder_port, 
                TCP_STATE_STRING[pcConnectionRow->responder_state], 
                pcConnectionRow->protocol, 
                pcConnectionRow->time_added);
    #endif

    /* Return whether both added successfully */
    return bIsAdded;
}

/**
 * Description: Adding a new TCP connection to connection table if needed
 *
 * Parameters:
 *		skb			        -	The packet
 *		pPacketInfo	        -	Pointer to packet info
 *      ppcConnectionRow    -   Pointer to pointer to TCP connection row    [out parameter]
 *
 * Return value: 
 *		BOOL		        -	Boolean indicator whether added successfully
 *
 */
BOOL addPacketToConnectionTableIfNeededTCP(struct sk_buff*      skb,  
                                           fw_packet_info*      pPacketInfo,
                                           connection_row_t**	ppcConnectionRow)
{
    /* Code Section */
    /* If not need to add to connection table */
    if (!isNeddedAddConnectionTCP(skb, pPacketInfo))
    {
        return FALSE;
    }  

    /* Adding TCP packet to connection table */
    return addTCPPacketToConnectionTable(pPacketInfo, ppcConnectionRow);
}

/**
 * Description: Returns whether connection establishment timeout has been reached
 *
 * Parameters:
 *		pcConnectionRow    -   Pointer to connection row
 *
 * Return value: 
 *		BOOL		        -	Boolean indicator whether connection establishment timeout has been reached
 *
 */
BOOL isEstablishmentTimeout(connection_row_t*           pConnectionRow)
{
    /* Struct Definition */
	struct timeval 			time;
    
	/* Code Section */
    /* If connection already established */
    if ((TCP_STATE_ESTABLISHED <= pConnectionRow->initiator_state) &&
        (TCP_STATE_ESTABLISHED <= pConnectionRow->responder_state))
    {
        /* Return false - already established */
        return FALSE;
    }

    /* Getting current timestamp */
	do_gettimeofday(&time);

    /* Return whether establishment timeout */
    return ((CONNECTION_ESTABLISHMENT_TIMEOUT_SECONDS < 
             (((unsigned long)time.tv_sec) - pConnectionRow->time_added)) 
            ? TRUE : FALSE);
}

/**
 * Description: Returns whether connection finished
 *
 * Parameters:
 *		pcConnectionRow    -   Pointer to connection row
 *
 * Return value: 
 *		BOOL		        -	Boolean indicator whether connection finished
 *
 */
BOOL isConnectionFinished(connection_row_t*             pConnectionRow)
{
	/* Code Section */
    /* Return if connection was finished */
    return ((
                ((TCP_STATE_FINISHED        ==  pConnectionRow->initiator_state) ||
                 (TCP_STATE_TIME_WAIT       ==  pConnectionRow->initiator_state) ||
                 (TCP_STATE_CLOSED          ==  pConnectionRow->initiator_state) ||
                 (TCP_STATE_BOTH_FINISHED   ==  pConnectionRow->initiator_state)) && 
                ((TCP_STATE_FINISHED        ==  pConnectionRow->responder_state) ||
                 (TCP_STATE_TIME_WAIT       ==  pConnectionRow->responder_state) ||
                 (TCP_STATE_CLOSED          ==  pConnectionRow->responder_state) ||
                 (TCP_STATE_BOTH_FINISHED   ==  pConnectionRow->responder_state))
            )
            ? TRUE : FALSE);
}

/**
 * Description: Returns whether connection row is irrelavent and can be deleted
 *              1. Establishment timeout
 *              2. Connection finished
 *
 * Parameters:
 *		pcConnectionRow    -   Pointer to connection row
 *
 * Return value: 
 *		BOOL		        -	Boolean indicator whether connection row is irrelavent and can be deleted
 *
 */
BOOL isIrrelaventTCPRow(connection_row_t*                       pcConnectionRow)
{
    /* Varaible Definition */
    BOOL                        bIsEstablishmentTimeout = FALSE;
    BOOL                        bIsConnectionFinished   = FALSE;

    /* Code Section */
    /* Checking protocol is TCP */
    if (PROTOCOL_CONNECTION_TCP == pcConnectionRow->protocol)
    {           
        /* If establishment timeout or connection has finished */
        if ((bIsEstablishmentTimeout = isEstablishmentTimeout(pcConnectionRow)) ||
            (bIsConnectionFinished   = isConnectionFinished(pcConnectionRow)))
        {
            #ifdef PRINT_DEBUG_MESSAGES
                if (bIsEstablishmentTimeout)
                {
                    printk(KERN_INFO REMOVE_ESTABLISHMENT_TIMEOUT_NODE_FRMT, 
                            CONNECTION_ROLE_STRING[CONNECTION_INITIATOR], 
                            pcConnectionRow->initiator_ip, 
                            pcConnectionRow->initiator_port, 
                            TCP_STATE_STRING[pcConnectionRow->initiator_state], 
                            CONNECTION_ROLE_STRING[CONNECTION_RESPONDER], 
                            pcConnectionRow->responder_ip, 
                            pcConnectionRow->responder_port, 
                            TCP_STATE_STRING[pcConnectionRow->responder_state], 
                            pcConnectionRow->protocol, 
                            pcConnectionRow->time_added);
                }
            #endif

            #ifdef PRINT_DEBUG_MESSAGES
                if (bIsConnectionFinished)
                {
                    printk(KERN_INFO REMOVE_CONNECTION_FINISHED_NODE_FRMT, 
                            CONNECTION_ROLE_STRING[CONNECTION_INITIATOR], 
                            pcConnectionRow->initiator_ip, 
                            pcConnectionRow->initiator_port, 
                            TCP_STATE_STRING[pcConnectionRow->initiator_state], 
                            CONNECTION_ROLE_STRING[CONNECTION_RESPONDER], 
                            pcConnectionRow->responder_ip, 
                            pcConnectionRow->responder_port, 
                            TCP_STATE_STRING[pcConnectionRow->responder_state], 
                            pcConnectionRow->protocol, 
                            pcConnectionRow->time_added);
                }
            #endif

            /* Return irrelevant */
            return TRUE;
        }
    }

    return FALSE;
}

/**
 * Description: Returns TCP packet flags
 *
 * Parameters:
 *		skb         -   The TCP packet
 *
 * Return value: 
 *		tcp_flags_t -	TCP packet flags
 *
 */
tcp_flags_t getTCPPacketFlags(struct sk_buff* skb)
{
	/* Struct Definition */
	struct iphdr* 			pHeaderIPv4;
	struct tcphdr*			pHeaderTCP;

	/* Variable Section */
    tcp_flags_t tfTCPFlags = TCP_FLAGS_INVALID;  

    /* Code Section */	
	/* If faulty non IPv4 packet */
	if ((!skb) || 
		(!(pHeaderIPv4 = ip_hdr(skb))))
	{
		return TCP_FLAGS_INVALID;
	}

	/* Validating TCP protocol */
	if (PROT_TCP == pHeaderIPv4->protocol)
	{
		/* Fetch TCP header */
		if (!(pHeaderTCP = (struct tcphdr *)((__u32 *)pHeaderIPv4 + pHeaderIPv4->ihl)))
		{
			return TCP_FLAGS_INVALID;
		}

        /* If rst flag is on */
		if (1 == pHeaderTCP->rst)
        {
            tfTCPFlags = TCP_FLAGS_RST;
        }         
        /* Else, if fin flag is on */
        else if (1 == pHeaderTCP->fin)
        {
            tfTCPFlags = TCP_FLAGS_FIN;

            /* If ack flag is on */
            if (1 == pHeaderTCP->ack)
            {
                tfTCPFlags = TCP_FLAGS_ACK_FIN;
            }
        }       
        /* Else, if syn flag is on */
        else if (1 == pHeaderTCP->syn)
        {
            tfTCPFlags = TCP_FLAGS_SYN;

            /* If ack flag is on */
            if (1 == pHeaderTCP->ack)
            {
                tfTCPFlags = TCP_FLAGS_ACK_SYN;
            }
        }  
        /* Else, if ack flag is on */
		else if (1 == pHeaderTCP->ack)
        {
            tfTCPFlags = TCP_FLAGS_ACK;

            /* If syn flag is on */
            if (1 == pHeaderTCP->syn)
            {
                tfTCPFlags = TCP_FLAGS_ACK_SYN;
            }
            /* Else, if fin flag is on */
            else if (1 == pHeaderTCP->fin)
            {
                tfTCPFlags = TCP_FLAGS_ACK_FIN;
            }
        }     
	}

	/* Return value */
	return tfTCPFlags;
}

/**
 * Description: Return whether state transtion match current state and incoming flags
 *
 * Parameters:
 *		tsConnectionState   -   Current connection state
 *		tfTCPFlags          -   The TCP flags of the incoming packet
 *		tsConnectionState   -   The state transition to check if match
 *
 * Return value: 
 *		BOOL                -	Boolean indicator whether state transtion match current state and incoming flags
 *
 */
BOOL isStateTransitionMatch(tcp_state_t                 tsConnectionState,
                            tcp_flags_t                 tfTCPFlags,
                            tcp_state_transition_t*     pctStateTransition)
{
    /* Code Section */
    return (((tsConnectionState ==  pctStateTransition->state       ) &&
             (tfTCPFlags        ==  pctStateTransition->flags_event ))
            ? TRUE : FALSE);
}

/**
 * Description: Handling if reset packet by closing the connection
 *
 * Parameters:
 *		tfTCPFlags          -   The TCP flags of the incoming packet
 *		pInitiatorState     -   The state of the connection initiator
 *		pResponderState     -   The state of the connection responder
 *
 * Return value: 
 *		BOOL                -	Boolean indicator whether its a reset flags and handeled
 *
 */
BOOL handlePacketTCPConnectionIsReset(tcp_flags_t        tfTCPFlags,
                                      unsigned int*      pInitiatorState,
                                      unsigned int*      pResponderState)
{
    /* Variable Definition */
    unsigned int    sInitiatorStateResetted = TCP_STATE_CLOSED;
    unsigned int    sResponderStateResetted = TCP_STATE_CLOSED;
    BOOL            bIsReset                = TCP_FLAGS_RST == tfTCPFlags;

    /* Code Section */
    /* If connection reset */
    if (bIsReset)
    {
        #ifdef PRINT_DEBUG_MESSAGES
            printk(KERN_INFO CLIENT_STATE_TRANSITION_FRMT, 
                TCP_STATE_STRING[*pInitiatorState], 
                TCP_STATE_STRING[sInitiatorStateResetted]);
        #endif

        /* Doing client state transition */
        *pInitiatorState = sInitiatorStateResetted;

        #ifdef PRINT_DEBUG_MESSAGES
            printk(KERN_INFO SERVER_STATE_TRANSITION_FRMT, 
                TCP_STATE_STRING[*pResponderState], 
                TCP_STATE_STRING[sResponderStateResetted]);
        #endif

        /* Doing server state transition */
        *pResponderState = sResponderStateResetted;
    }

    /* Return wether connection reset */
    return bIsReset;
}

/**
 * Description: Handling connection initiator state transition
 *
 * Parameters:
 *		tfTCPFlags          -   The TCP flags of the incoming packet
 *		pInitiatorState     -   The state of the connection initiator
 *		pResponderState     -   The state of the connection responder
 *
 * Return value: 
 *		BOOL                -	Boolean indicator whether handeled
 *
 */
verdict_t handlePacketTCPConnectionInitiator(tcp_flags_t        tfTCPFlags,
                                             unsigned int*      pInitiatorState,
                                             unsigned int*      pResponderState)
{
    /* Varaible Definition */
    tcp_state_transition_t* pctClientTransition;
    tcp_state_transition_t* pctServerTransition;
    unsigned int            uClientTransitionIndex  = 0;
    unsigned int            uServerTransitionIndex  = 0;

    /* Code Section */
    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO INITIATOR_IS_THE_PACKET_SENDER_FRMT,
            TCP_STATE_STRING[*pInitiatorState], 
            TCP_FLAGS_STRING[tfTCPFlags],
            TCP_STATE_STRING[*pResponderState]);
    #endif

    /* Checking if connection reset */
    if (handlePacketTCPConnectionIsReset(tfTCPFlags, pInitiatorState, pResponderState))
    {
        /* Return allow */
        return VERDICT_ALLOW;
    }

    /* Going over the client state transitions */
    for (uClientTransitionIndex = 0; 
         (sizeof(tcp_client_sends_server_transition_table)/sizeof(tcp_state_transition_t)) > 
          uClientTransitionIndex; 
         ++uClientTransitionIndex)
    {
        /* Fetching current possible state transition */
        pctClientTransition = &(tcp_client_sends_server_transition_table[uClientTransitionIndex]);

        /* If current state transition matches sender state and packet flags */
        if (isStateTransitionMatch((tcp_state_t)*pInitiatorState, 
                                   tfTCPFlags, 
                                   pctClientTransition))
        {
            /* Going over the server state transitions */
            for (uServerTransitionIndex = 0; 
                 (sizeof(tcp_server_recives_client_transition_table)/sizeof(tcp_state_transition_t)) > 
                  uServerTransitionIndex; 
                 ++uServerTransitionIndex)
            {
                /* Fetching current possible state transition */
                pctServerTransition = &(tcp_server_recives_client_transition_table[uServerTransitionIndex]);

                /* If current state transition matches reciver state and packet flags */
                if (isStateTransitionMatch((tcp_state_t)*pResponderState, 
                                           tfTCPFlags, 
                                           pctServerTransition))
                {
                    #ifdef PRINT_DEBUG_MESSAGES
                        printk(KERN_INFO CLIENT_STATE_TRANSITION_FRMT, 
                            TCP_STATE_STRING[pctClientTransition->state], 
                            TCP_STATE_STRING[pctClientTransition->next_state]);
                    #endif

                    /* Doing client state transition */
                    *pInitiatorState = pctClientTransition->next_state;

                    #ifdef PRINT_DEBUG_MESSAGES
                        printk(KERN_INFO SERVER_STATE_TRANSITION_FRMT, 
                            TCP_STATE_STRING[pctServerTransition->state], 
                            TCP_STATE_STRING[pctServerTransition->next_state]);
                    #endif

                    /* Doing server state transition */
                    *pResponderState = pctServerTransition->next_state;

                    /* Return allow */
                    return VERDICT_ALLOW;
                }
            }
        }
    }

    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO NO_VALID_TCP_STATE_TRANSITION_FOUND);
    #endif

    /* Return block */
    return VERDICT_BLOCK;
}

/**
 * Description: Handling connection initiator state transition, according to packet direction
 *
 * Parameters:
 *		tfTCPFlags          -   The TCP flags of the incoming packet
 *		pcConnectionRow     -   Pointer to connection row
 *		netfilter_direction -   Packet direction (incoming or outgoing from firewall)
 *
 * Return value: 
 *		verdict_t           -	Packet verdict
 *
 */
verdict_t handlePacketTCPConnectionInitiatorByDirection(tcp_flags_t             tfTCPFlags,
                                                        connection_row_t*       pcConnectionRow,
                                                        netfilter_direction_t   netfilter_direction)
{
    /* Variable Definition */
    verdict_t       vVerdict            =   VERDICT_BLOCK;

    /* Code Section */
    /* Handling according to direction */
    switch (netfilter_direction)
    {
        /* Packet incoming */
        case (INPUT_PACKET):
        {
            #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO PACKET_INCOMING_INITIATOR_TO_PROXY);
            #endif
            
            /* Packet incoming [initiator -> proxy] */
            vVerdict = 
                handlePacketTCPConnectionInitiator(tfTCPFlags,
                                                   &(pcConnectionRow->initiator_state),
                                                   &(pcConnectionRow->proxy_responder_state));

            /* End of case */
            break;
        }

        /* Packet outgoing */
        case (OUTPUT_PACKET):
        {
            #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO PACKET_OUTGOING_PROXY_TO_RESPONDER);
            #endif

            /* Packet outgoing [proxy -> responder] */
            vVerdict = 
                handlePacketTCPConnectionInitiator(tfTCPFlags,
                                                   &(pcConnectionRow->proxy_initiator_state),
                                                   &(pcConnectionRow->responder_state));

            /* End of case */
            break;
        }

        /* Invalid direction */
        default:
        {
            #ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR PACKET_DIRECTION_IS_INVALID_FOR_TRANSITION_FRMT, netfilter_direction);
			#endif

            /* Verdict block */
            vVerdict = VERDICT_BLOCK;
        }
    }

    /* Return verdict */
    return vVerdict;
}

/**
 * Description: Handling connection responder state transition
 *
 * Parameters:
 *		tfTCPFlags          -   The TCP flags of the incoming packet
 *		pInitiatorState     -   The state of the connection initiator
 *		pResponderState     -   The state of the connection responder
 *
 * Return value: 
 *		BOOL                -	Boolean indicator whether handeled
 *
 */
verdict_t handlePacketTCPConnectionResponder(tcp_flags_t        tfTCPFlags,
                                             unsigned int*      pInitiatorState,
                                             unsigned int*      pResponderState)
{
    /* Varaible Definition */
    tcp_state_transition_t* pctClientTransition;
    tcp_state_transition_t* pctServerTransition;
    unsigned int            uClientTransitionIndex  = 0;
    unsigned int            uServerTransitionIndex  = 0;

    /* Code Section */
    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO RESPONDER_IS_THE_PACKET_SENDER_FRMT,  
            TCP_STATE_STRING[*pInitiatorState], 
            TCP_FLAGS_STRING[tfTCPFlags],
            TCP_STATE_STRING[*pResponderState]);
    #endif

    /* Checking if connection reset */
    if (handlePacketTCPConnectionIsReset(tfTCPFlags, pInitiatorState, pResponderState))
    {
        /* Return allow */
        return VERDICT_ALLOW;
    } 

    /* Going over the server state transitions */
    for (uServerTransitionIndex = 0; 
         (sizeof(tcp_server_sends_client_transition_table)/sizeof(tcp_state_transition_t)) > 
         uServerTransitionIndex; 
         ++uServerTransitionIndex)
    {
        /* Fetching current possible state transition */
        pctServerTransition = &(tcp_server_sends_client_transition_table[uServerTransitionIndex]);

        /* If current state transition matches reciver state and packet flags */
        if (isStateTransitionMatch((tcp_state_t)*pResponderState, 
                                   tfTCPFlags, 
                                   pctServerTransition))
        {
            /* Going over the client state transitions */
            for (uClientTransitionIndex = 0; 
                 (sizeof(tcp_client_recives_server_transition_table)/sizeof(tcp_state_transition_t)) > 
                  uClientTransitionIndex; 
                 ++uClientTransitionIndex)
            {
                /* Fetching current possible state transition */
                pctClientTransition = &(tcp_client_recives_server_transition_table[uClientTransitionIndex]);

                /* If current state transition matches sender state and packet flags */
                if (isStateTransitionMatch((tcp_state_t)*pInitiatorState, 
                                           tfTCPFlags, 
                                           pctClientTransition))
                {
                    #ifdef PRINT_DEBUG_MESSAGES
                        printk(KERN_INFO CLIENT_STATE_TRANSITION_FRMT, 
                                    TCP_STATE_STRING[pctClientTransition->state], 
                                    TCP_STATE_STRING[pctClientTransition->next_state]);
                    #endif
                    
                    /* Doing client state transition */
                    *pInitiatorState = pctClientTransition->next_state;

                    #ifdef PRINT_DEBUG_MESSAGES
                        printk(KERN_INFO SERVER_STATE_TRANSITION_FRMT, 
                            TCP_STATE_STRING[pctServerTransition->state], 
                            TCP_STATE_STRING[pctServerTransition->next_state]);
                    #endif

                    /* Doing server state transition */
                    *pResponderState = pctServerTransition->next_state;

                    /* Return allow */
                    return VERDICT_ALLOW;
                }
            }
        }
    }

    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO NO_VALID_TCP_STATE_TRANSITION_FOUND);
    #endif

    /* Return block */
    return VERDICT_BLOCK;
}

/**
 * Description: Handling connection responder state transition, according to packet direction
 *
 * Parameters:
 *		tfTCPFlags          -   The TCP flags of the incoming packet
 *		pcConnectionRow     -   Pointer to connection row
 *		netfilter_direction -   Packet direction (incoming or outgoing from firewall)
 *
 * Return value: 
 *		verdict_t           -	Packet verdict
 *
 */
verdict_t handlePacketTCPConnectionResponderByDirection(tcp_flags_t             tfTCPFlags,
                                                        connection_row_t*       pcConnectionRow,
                                                        netfilter_direction_t   netfilter_direction)
{
    /* Variable Definition */
    verdict_t       vVerdict            =   VERDICT_BLOCK;

    /* Code Section */
    /* Handling according to direction */
    switch (netfilter_direction)
    {
        /* Packet incoming */
        case (INPUT_PACKET):
        {
            #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO PACKET_INCOMING_RESPONDER_TO_PROXY);
            #endif

            /* Packet incoming [responder -> proxy] */
            vVerdict = 
                handlePacketTCPConnectionResponder(tfTCPFlags,
                                                   &(pcConnectionRow->proxy_initiator_state),
                                                   &(pcConnectionRow->responder_state));

            /* End of case */
            break;
        }

        /* Packet outgoing */
        case (OUTPUT_PACKET):
        {
            #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO PACKET_INCOMING_PROXY_TO_INITIATOR);
            #endif

            /* Packet outgoing [proxy -> initiator] */
            vVerdict = 
                handlePacketTCPConnectionResponder(tfTCPFlags,
                                                   &(pcConnectionRow->initiator_state),
                                                   &(pcConnectionRow->proxy_responder_state));
            
            /* End of case */
            break;
        }

        /* Invalid direction */
        default:
        {
            #ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR PACKET_DIRECTION_IS_INVALID_FOR_TRANSITION_FRMT, netfilter_direction);
			#endif

            /* Verdict block */
            vVerdict = VERDICT_BLOCK;
        }
    }

    /* Return verdict */
    return vVerdict;
}

/**
 * Description: Handling connection state transition
 *
 * Parameters:
 *      skb                 -   The packet
 *      pPacketInfo         -   Pointer to packet information
 *		trSenderRole        -   Packet sender role
 *		pcConnectionRow     -   Pointer to connection row
 *
 * Return value: 
 *		verdict_t           -	Packet verdict
 *
 */
verdict_t handlePacketTCPConnection(struct sk_buff*             skb,
                                    fw_packet_info*             pPacketInfo,
                                    connection_role_t           trSenderRole, 
                                    connection_row_t*           pcConnectionRow)
{
    /* Varaible Definition */
    tcp_flags_t tfTCPFlags  = TCP_FLAGS_INVALID; 
    verdict_t   vVerdict    = VERDICT_BLOCK;

    /* Code Section */
    /* Fetching TCP packet flags */
    if (TCP_FLAGS_INVALID == (tfTCPFlags = getTCPPacketFlags(skb)))
    {
        #ifdef PRINT_DEBUG_MESSAGES
            printk(KERN_ERR PACKET_TCP_FLSGS_ARE_INVALID_COMBINATION);
        #endif

        /* Invalid falgs combination detected - block */
        return VERDICT_BLOCK;
    }

	/* Handling packet according to sender role */
    switch (trSenderRole)
    {    
        /* In case it's connection initiator AKA client */
        case (CONNECTION_INITIATOR):
        {
            /* Handle TCP initiator packet */
            vVerdict = handlePacketTCPConnectionInitiatorByDirection(tfTCPFlags, pcConnectionRow, pPacketInfo->netfilter_direction);

            /* End of case */
            break;
        }

        /* In case it's connection responder AKA server */
        case (CONNECTION_RESPONDER):
        {
            /* Handle TCP responder packet */
            vVerdict = handlePacketTCPConnectionResponderByDirection(tfTCPFlags, pcConnectionRow, pPacketInfo->netfilter_direction);

            /* End of case */
            break;
        }
    }

    /* Return packet verdict */
    return vVerdict;
}
