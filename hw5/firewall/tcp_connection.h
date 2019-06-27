#ifndef _TCP_CONNETION_H_
#define _TCP_CONNETION_H_

#include <linux/time.h>

#include "fw.h"
#include "debug.h"
#include "bool.h"
#include "packet_verdict.h"

#include "connection_table.h"

/* Define Section */
#define CONNECTION_ESTABLISHMENT_TIMEOUT_SECONDS        (25)

/* Messages */
#define PACKET_TCP_FLSGS_ARE_INVALID_COMBINATION		" Packet TCP flags are invalid combination.\n"
#define INITIATOR_IS_THE_PACKET_SENDER_FRMT		        " Initiator (client) is the packet sender,\n\tClient=[%s] Flags=[%s] Server=[%s].\n"
#define RESPONDER_IS_THE_PACKET_SENDER_FRMT		        " Responder (server) is the packet sender,\n\tClient=[%s] Flags=[%s] Server=[%s].\n"

#define CLIENT_STATE_TRANSITION_FRMT		            " Client state transition from %s to %s.\n"
#define SERVER_STATE_TRANSITION_FRMT		            " Server state transition from %s to %s.\n"

#define PACKET_DIRECTION_IS_INVALID_FOR_TRANSITION_FRMT " Packet direction [%d] is ivalid for transition.\n"

#define NO_VALID_TCP_STATE_TRANSITION_FOUND             " No valid TCP state transition found.\n"

#define REMOVE_ESTABLISHMENT_TIMEOUT_NODE_FRMT          " TCP Establishment timeout node remove " CONECTION_ROW_PRINT_FRMT
#define REMOVE_CONNECTION_FINISHED_NODE_FRMT            " TCP connection finished node remove " CONECTION_ROW_PRINT_FRMT

/* Enum Section */
#define FOREACH_TCP_STATE(TCP_STATE) \
            TCP_STATE(TCP_STATE_LISTEN) \
            TCP_STATE(TCP_STATE_SYN_SENT) \
            TCP_STATE(TCP_STATE_SYN_RECEIVED) \
            TCP_STATE(TCP_STATE_ESTABLISHED) \
            TCP_STATE(TCP_STATE_CLOSE_WAIT) \
            TCP_STATE(TCP_STATE_LAST_ACK) \
            TCP_STATE(TCP_STATE_FIN_WAIT_1) \
            TCP_STATE(TCP_STATE_FIN_WAIT_2) \
            TCP_STATE(TCP_STATE_CLOSING) \
            TCP_STATE(TCP_STATE_FINISHED) \
            TCP_STATE(TCP_STATE_OTHER_FINISHED) \
            TCP_STATE(TCP_STATE_TIME_WAIT) \
            TCP_STATE(TCP_STATE_CLOSED) \
            TCP_STATE(TCP_STATE_BOTH_FINISHED) \

#define FOREACH_TCP_FLAGS(TCP_FLAGS) \
            TCP_FLAGS(TCP_FLAGS_ACK) \
            TCP_FLAGS(TCP_FLAGS_SYN) \
            TCP_FLAGS(TCP_FLAGS_FIN) \
            TCP_FLAGS(TCP_FLAGS_RST) \
            TCP_FLAGS(TCP_FLAGS_ACK_SYN) \
            TCP_FLAGS(TCP_FLAGS_ACK_FIN) \
            TCP_FLAGS(TCP_FLAGS_INVALID) \

#ifndef ENUM_GENERATORS
	#define ENUM_GENERATORS
	#define GENERATE_ENUM(ENUM) 	ENUM,
	#define GENERATE_STRING(STRING) #STRING,
#endif

typedef enum tcp_state_t {
    FOREACH_TCP_STATE(GENERATE_ENUM)
} tcp_state_t;

typedef enum tcp_flags_t {
    FOREACH_TCP_FLAGS(GENERATE_ENUM)
} tcp_flags_t;

#ifdef PRINT_DEBUG_MESSAGES
	static const char* TCP_STATE_STRING[] = {        
		FOREACH_TCP_STATE(GENERATE_STRING)
	};

    static const char* TCP_FLAGS_STRING[] = {        
		FOREACH_TCP_FLAGS(GENERATE_STRING)
	};
#endif

/* Struct Section */
typedef struct tcp_state_transition_t {
    tcp_state_t     state;
    tcp_flags_t     flags_event;
    tcp_state_t     next_state;
} tcp_state_transition_t;

/* Methods Section */
BOOL isConnectionTableVerdictTCP(struct sk_buff*	            skb,
						 	     fw_packet_info* 	            pPacketInfo);

BOOL addPacketToConnectionTableIfNeededTCP(struct sk_buff*      skb,  
                                           fw_packet_info*      pPacketInfo,
                                           connection_row_t**	ppcConnectionRow);

BOOL addNewTCPToConnectionTable(new_connection_raw_t*           pNewConnection);

BOOL isIrrelaventTCPRow(connection_row_t*                       pConnectionRow);

verdict_t handlePacketTCPConnection(struct sk_buff*             skb,
                                    fw_packet_info*             pPacketInfo,
                                    connection_role_t           trSenderRole, 
                                    connection_row_t*           pcConnectionRow);

#ifdef PRINT_DEBUG_MESSAGES
tcp_flags_t getTCPPacketFlags(struct sk_buff* skb);
#endif

#endif
