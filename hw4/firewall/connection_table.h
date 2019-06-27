#ifndef _CONNECTION_TABLE_H_
#define _CONNECTION_TABLE_H_

#include <linux/list.h>
#include <linux/time.h>

#include "fw.h"
#include "bool.h"
#include "debug.h"
#include "connection_dev.h"
#include "packet_verdict.h"

/* Define Section */
/* Messages */
#define CONNECTION_ADDED      				            " Connection added!\n"
#define SETTING_PACKET_VERDICT_BY_CONNECTION_TABLE      " Setting packet verdict by connection table.\n"
#define PACKET_CONNECTION_ROW_NOT_FOUND				    " Packet connection row not found.\n"
#define PACKET_CONNECTION_ROW_FOUND			            " Packet connection row found.\n"
#define PACKET_CONNECTION_PROTOCOL_IS_ILLEGAL			" Packet connection protocol is illegal.\n"
#define PACKET_CONNECTION_ROW_ALREADY_EXISTS            " Packet connection already exists.\n"
#define PACKET_PROTOCOL_UNRECOGNIZED    				" Packet protocol unrecognized.\n"
#define PACKET_PROTOCOL_VALID_ADD_IT_FRMT    			" Packet protocol is valid; %hhu, add it.\n"

#define PACKET_INCOMING_INITIATOR_TO_PROXY              " Packet incoming [initiator    ->  proxy]\n"
#define PACKET_OUTGOING_PROXY_TO_RESPONDER              " Packet outgoing [proxy        ->  responder]\n"
#define PACKET_INCOMING_RESPONDER_TO_PROXY              " Packet incoming [responder    ->  proxy]\n"
#define PACKET_INCOMING_PROXY_TO_INITIATOR              " Packet outgoing [proxy        ->  initiator]\n"

/* Debug Print */
#define CONECTION_TABLE                                 "### Connection Table: ### \n"
#define CONECTION_ROW_PRINT_FRMT                        "\tRole:%s [%X %hu] State: [%s]\n\tRole:%s [%X %hu] State: [%s]\n Protocol: [%u] Time added: [%lu]\n"
#define CONECTION_ROW_ADDED_FRMT                        " Connection row added; \n" CONECTION_ROW_PRINT_FRMT
#define CONECTION_ROW_REMOVED_FRMT                      " Connection row removed; \n" CONECTION_ROW_PRINT_FRMT
#define TOTAL_CONECTION_ROWS_FRMT                       " Total connection rows: %u \n "

/* Enum Section */
typedef enum connection_protocols_t {
    PROTOCOL_CONNECTION_TCP = PROT_TCP,
    PROTOCOL_CONNECTION_FTP,
    PROTOCOL_CONNECTION_HTTP,
    PROTOCOL_CONNECTION_SMTP,
} connection_protocols_t;

#define FOREACH_CONNECTION_ROLE(CONNECTION_ROLE) \
            CONNECTION_ROLE(CONNECTION_INITIATOR) \
            CONNECTION_ROLE(CONNECTION_RESPONDER) \

#ifndef ENUM_GENERATORS
	#define ENUM_GENERATORS
	#define GENERATE_ENUM(ENUM) 	ENUM,
	#define GENERATE_STRING(STRING) #STRING,
#endif

typedef enum connection_role_t {
    FOREACH_CONNECTION_ROLE(GENERATE_ENUM)
} connection_role_t;

#ifdef PRINT_DEBUG_MESSAGES
	static const char* CONNECTION_ROLE_STRING[] = {        
		FOREACH_CONNECTION_ROLE(GENERATE_STRING)
	};
#endif

typedef struct connection_row_t {
    unsigned int   		    initiator_ip;		
	unsigned short 			initiator_port;

	unsigned int			responder_ip;	
	unsigned short 			responder_port;

    connection_protocols_t  protocol;

    unsigned int            initiator_state;
    unsigned int            proxy_responder_state;

    unsigned int            proxy_initiator_state;
    unsigned int            responder_state;

    unsigned long 			time_added;

    struct list_head        connection_rows_list;
} connection_row_t;

/* Methods Section */
EDevReturnValue connection_table_device_init(struct class*              pcFirewallClass);
void connection_table_device_destroy(struct class*                      pcFirewallClass);

void logPacket(fw_packet_info* 	                                        pPacketInfo);

BOOL    addToConnectionTable(connection_row_t*                          pcConnectionRow);

BOOL isConnectionExists(fw_packet_info*                                 pPacketInfo);

BOOL    isConnectionTableVerdict(struct sk_buff*	                    skb,
						 	     fw_packet_info* 	                    pPacketInfo);

BOOL    addPacketToConnectionTableIfNeeded(struct sk_buff*              skb,
                                           fw_packet_info*              pPacketInfo,
                                           connection_row_t**	        ppcConnectionRow);

BOOL    setIncomingPacketVerdictByConnectionTable(struct sk_buff*       skb,
                                                  fw_packet_info*       pPacketInfo,
									              connection_row_t**    ppcConnectionRow);

BOOL    setOutgoingPacketVerdictByConnectionTable(struct sk_buff*       skb,
                                                  fw_packet_info*       pPacketInfo,
                                                  connection_role_t*    pSenderRole,
									              connection_row_t**    ppcConnectionRow);

BOOL findConnectionRow(fw_packet_info*                                  pPacketInfo, 
                       connection_role_t*                               pRole,
                       connection_row_t**                               ppcrConnectionRow,
                       BOOL                                             bIsFromProxy);

#ifdef PRINT_DEBUG_MESSAGES
void printConnectionTable(void);
#endif

#endif
