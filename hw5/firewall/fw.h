#ifndef _FW_H_
#define _FW_H_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <net/tcp.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bool.h"
#include "basic_messages.h"


/* Firewall IPs */
#define FIREWALL_IP1										0xA010103  /* 10.1.1.3 */
#define FIREWALL_IP2										0xA010203  /* 10.1.2.3 */

/* Policies */
#define DEFAULT_ALLOW_OUTER_PACKETS							1

/* Basic Print */
#define STRING_NEW_LINE_FORMAT								"%s\n"

// the protocols we will work with
typedef enum {
	PROT_ICMP	= 1,
	PROT_TCP	= 6,
	PROT_UDP	= 17,
	PROT_OTHER 	= 255,
	PROT_ANY	= 143,
} prot_t;

typedef enum {
	PORT_HTTP			= 80,
	PORT_FTP_DATA		= 20,
	PORT_FTP_COMMAND	= 21,
	PORT_SSH			= 22,
	PORT_SMTP			= 25,
	
	FIREWALL_PORT 		= 9000,

	FIREWALL_PORT_IN	= FIREWALL_PORT + 100,
	FIREWALL_PORT_OUT	= FIREWALL_PORT + 200,
} port_stateful_t;

// various reasons to be registered in each log entry
typedef enum {
	REASON_ABSENT				 		=  0,
	REASON_FW_INACTIVE           		= -1,
	REASON_NO_MATCHING_RULE      		= -2,
	REASON_XMAS_PACKET           		= -4,
	REASON_ILLEGAL_VALUE         		= -6,
	REASON_CONNECTION_TABLE_VERDICT  	= -7,
	REASON_CONNECTION_NOT_FOUND			= -8,
	REASON_CONNECTION_PROTOCOL_ILLEGAL	= -9,
	REASON_CONNECTION_ALREADY_EXISTS	= -10,
	REASON_OUTER_PACKET					= -11,
} reason_t;
	
// IP Addresses
#define LOCALHOST_IP				0x7F000001

// auxiliary strings, for your convenience
#define DEVICE_NAME_RULES			"rules"
#define DEVICE_NAME_LOG				"log"
#define DEVICE_NAME_CONN_TAB		"conn_tab"
#define CLASS_NAME					"fw"
#define LOOPBACK_NET_DEVICE_NAME	"lo"
#define IN_NET_DEVICE_NAME			"eth1"
#define OUT_NET_DEVICE_NAME			"eth2"

// auxiliary values, for your convenience
#define IP_VERSION		(4)
#define PORT_ANY		(0)
#define PORT_ABOVE_1023	(1023)
#define MAX_RULES		(50)

// device minor numbers, for your convenience
typedef enum {
	MINOR_RULES    = 0,
	MINOR_LOG      = 1,
	MINOR_CONN_TAB = 2,
} minor_t;

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

typedef enum {
	INPUT_PACKET 	= 0x01,
	OUTPUT_PACKET 	= 0x02,	
} netfilter_direction_t;

typedef enum {
	DESTINATION_UNCHANGED 				= 0,
	DESTINATION_TO_FIREWALL_SERVER 		= 1,
	DESTINATION_FROM_FIREWALL_SERVER 	= 2,
} destination_t;

// rule base
typedef struct {
	char rule_name[20];			// names will be no longer than 20 chars
	direction_t direction;
	__be32	src_ip;
	__be32	src_prefix_mask; 	// e.g., 255.255.255.0 as int in the local endianness
	__u8    src_prefix_size; 	// valid values: 0-32, e.g., /24 for the example above
								// (the field is redundant - easier to print)
	__be32	dst_ip;
	__be32	dst_prefix_mask; 	// as above
	__u8    dst_prefix_size; 	// as above	
	__be16	src_port; 			// number of port or 0 for any or port 1023 for any port number > 1023  
	__be16	dst_port; 			// number of port or 0 for any or port 1023 for any port number > 1023 
	__u8	protocol; 			// values from: prot_t
	ack_t	ack; 				// values from: ack_t
	__u8	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_t;

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	__be32   		src_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be32			dst_ip;		  	// if you use this struct in userspace, change the type to unsigned int
	__be16 			src_port;	  	// if you use this struct in userspace, change the type to unsigned short
	__be16 			dst_port;	  	// if you use this struct in userspace, change the type to unsigned short
	reason_t     	reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits

	struct list_head log_rows_list;	// log rows kernel list
} log_row_t;

typedef struct fw_packet_info {
	unsigned long  			timestamp;  
	unsigned char  			protocol;   
	unsigned char  			action;     
	unsigned char  			hooknum;    
	__be32   				src_ip;		
	__be32					dst_ip;		
	__be16 					src_port;	
	__be16 					dst_port;	
	reason_t     			reason;	
	direction_t				direction;
	netfilter_direction_t	netfilter_direction;
	ack_t					ack;	
} fw_packet_info;

#endif // _FW_H_