#ifndef _USER_FW_H_
#define _USER_FW_H_

#define USER_MODE										1

/* Defined in fw.h */
#define DEVICE_NAME_RULES								"rules"
#define DEVICE_NAME_LOG									"log"
#define DEVICE_NAME_CONN_TAB							"conn_tab"
#define CLASS_NAME										"fw"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

/* Defined in fw.h */
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;

typedef enum {
	ACK_NO 		= 0x01,
	ACK_YES 	= 0x02,
	ACK_ANY 	= ACK_NO | ACK_YES,
} ack_t;

typedef enum {
	DIRECTION_IN 	= 0x01,
	DIRECTION_OUT 	= 0x02,
	DIRECTION_ANY 	= DIRECTION_IN | DIRECTION_OUT,
} direction_t;

// various reasons to be registered in each log entry
typedef enum {
	REASON_FW_INACTIVE           = -1,
	REASON_NO_MATCHING_RULE      = -2,
	REASON_XMAS_PACKET           = -4,
	REASON_ILLEGAL_VALUE         = -6,
} reason_t;

/* Defined in fw.h */

typedef enum rule_indexes {
	rule_indexes_rule_name = 0,	
	rule_indexes_direction,
	rule_indexes_Source_IP,
	rule_indexes_Dest_IP,
	rule_indexes_protocol,
	rule_indexes_Source_port,
	rule_indexes_Dest_port,
	rule_indexes_ack,
	rule_indexes_action,
} rule_indexes;

/* Struct Section */
typedef struct {
	char 			rule_name[20];		// names will be no longer than 20 chars
	direction_t 	direction;
	unsigned int	src_ip;
	unsigned int	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	unsigned char   src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
										// (the field is redundant - easier to print)
	unsigned int	dst_ip;
	unsigned int	dst_prefix_mask; 	// as above
	unsigned char	dst_prefix_size; 	// as above	
	unsigned short	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	unsigned short	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	unsigned char	protocol; 			// values from: prot_t
	ack_t			ack; 				// values from: ack_t
	unsigned char	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

/* Defined in fw.h */

#endif
