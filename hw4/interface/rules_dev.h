#ifndef _RULES_DEV_H_
#define _RULES_DEV_H_

#ifdef USER_MODE
#include "user_sysfs_dev.h"
#else
#include "sysfs_dev.h"
#endif

/* Rules Device Section */
#define FW_DEVICE_NAME_RULES							"fw_rules"
#define DEVICE_RULES_ACTION_ACTIVATE					"active"
#define DEVICE_RULES_ACTION_RULES_SIZE					"rules_size"
#define RULES_DEVICE 									DEVICE_PREFIX FW_DEVICE_NAME_RULES

/* Rules Sysfs Section */
#define SYSFS_RULES_PATH								SYSFS_PATH_PREFIX CLASS_NAME "/" FW_DEVICE_NAME_RULES "/"
#define SYSFS_RULES_ATTRIBUTE_ACTIVATE_PATH				SYSFS_RULES_PATH DEVICE_RULES_ACTION_ACTIVATE
#define SYSFS_RULES_ATTRIBUTE_RULES_SIZE_PATH			SYSFS_RULES_PATH DEVICE_RULES_ACTION_RULES_SIZE

/* User Actions */
#ifndef USER_ACTIONS_RULES
#define USER_ACTIONS_RULES
#define	ACTIVATE_ACTION									"activate"
#define	DEACTIVATE_ACTION								"deactivate"
#define	SHOW_RULES_ACTION								"show_rules"
#define	CLEAR_RULES_ACTION								"clear_rules"
#define	LOAD_RULES_ACTION								"load_rules"
#endif

/*
 * Rule Format: 
 * <rule_name> <direction> <Source_IP>/<nps> <Dest_IP>/<nps> <protocol> <Source_port> <Dest_port> <ack> <action> 
 */
/* Begin of Rule Defines Region */
#define RULE_DELIMETER          						" "
#define RULE_DELIMETER_LENGTH   						1  /* strlen(RULE_DELIMETER) */
#define DELIMETERS_IN_RULE      						8
#define TOKENS_IN_RULE      							(DELIMETERS_IN_RULE+1)

/* Rule Minimal Length */
#define RULE_MIN_NAME_LENGTH							1  /* At least one letter to distinguish */
#define DIRECTION_MIN_LENGTH    						2  /* min[strlen("in", "out", "any")] */
#define IP_MIN_LENGTH           						3  /* min[strlen("any", "0.0.0.0/0")] */
#define PROTOCOL_MIN_LENGTH     						3  /* min[strlen("any", "icmp", "tcp", "udp", "other")] */
#define PORT_MIN_LENGTH         						1  /* min[strlen("any", "p", ">1023")] */
#define ACK_MIN_LENGTH          						2  /* min[strlen("any", "no", "yes")] */
#define ACTION_MIN_LENGTH       						4  /* min[strlen("accept", "drop")] */
#define RULE_MIN_LENGTH         						(RULE_MIN_NAME_LENGTH + \
                                						 DIRECTION_MIN_LENGTH + \
                                						 IP_MIN_LENGTH + \
                                						 IP_MIN_LENGTH + \
                                						 PROTOCOL_MIN_LENGTH + \
                                						 PORT_MIN_LENGTH + \
                                						 PORT_MIN_LENGTH + \
                                						 ACK_MIN_LENGTH + \
                                						 ACTION_MIN_LENGTH + \
                                						 (DELIMETERS_IN_RULE * RULE_DELIMETER_LENGTH))

/* Rule Maximal Length */
#define RULE_MAX_NAME_LENGTH							19 /* As defined in fw.h (20 chars: name + '\0') */
#define DIRECTION_MAX_LENGTH    						3  /* max[strlen("in", "out", "any")] */
#define PREFIX_MAX_LENGTH       						2  /* max[strlen("31")] */
#define IP_MAX_LENGTH           						18 /* max[strlen("any", "255.255.255.255/31")] */
#define PROTOCOL_MAX_LENGTH     						5  /* max[strlen("any", "icmp", "tcp", "udp", "other")] */
#define PORT_MAX_LENGTH         						5  /* max[strlen("any", "ppppp", ">1023")] */
#define ACK_MAX_LENGTH          						3  /* max[strlen("any", "no", "yes")] */
#define ACTION_MAX_LENGTH       						6  /* max[strlen("accept", "drop")] */
#define RULE_MAX_LENGTH         						(RULE_MAX_NAME_LENGTH + \
                                						 DIRECTION_MAX_LENGTH + \
                                						 IP_MAX_LENGTH + \
                                						 IP_MAX_LENGTH + \
                                						 PROTOCOL_MAX_LENGTH + \
                                						 PORT_MAX_LENGTH + \
                                						 PORT_MAX_LENGTH + \
                                						 ACK_MAX_LENGTH + \
                                						 ACTION_MAX_LENGTH + \
                                						 (DELIMETERS_IN_RULE * RULE_DELIMETER_LENGTH))

/* Rule Dev Format */				
#define	RULE_DEV_ITEM_SEPERATOR							"|"
#define	RULE_DEV_FIELD_SEPERATOR						" "

#define FIELDS_IN_RULE_DEV								13
#define SEPERATORS_IN_RULE_DEV							14 /* strlen(FIELDS_IN_RULE_DEV*RULE_DEV_FIELD_SEPERATOR + RULE_DEV_ITEM_SEPERATOR) */

#define RULE_DEV_FORMAT									(STRING_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 DECIMAL_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 USHRT_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 USHRT_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 DECIMAL_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT RULE_DEV_FIELD_SEPERATOR \
														 RULE_DEV_ITEM_SEPERATOR)

/* Rule Dev Max Format Length */				
#define RULE_DEV_MAX_RULE_NAME_LEN						(RULE_MAX_NAME_LENGTH+1)
#define RULE_DEV_MAX_DIRECTION_LEN						UCHAR_MAX_LEN
#define RULE_DEV_MAX_SRC_IP_LEN							UINT_MAX_LEN
#define RULE_DEV_MAX_SRC_PREFIX_MASK_LEN				UINT_MAX_LEN
#define RULE_DEV_MAX_SRC_PREFIX_SIZE_LEN				UCHAR_MAX_LEN
#define RULE_DEV_MAX_DST_IP_LEN							UINT_MAX_LEN
#define RULE_DEV_MAX_DST_PREFIX_MASK_LEN				UINT_MAX_LEN
#define RULE_DEV_MAX_DST_PREFIX_SIZE_LEN				UCHAR_MAX_LEN
#define RULE_DEV_MAX_SRC_PORT_LEN						USHRT_MAX_LEN
#define RULE_DEV_MAX_DST_PORT_LEN						USHRT_MAX_LEN
#define RULE_DEV_MAX_PROTOCOL_LEN						UCHAR_MAX_LEN
#define RULE_DEV_MAX_ACK_LEN							UCHAR_MAX_LEN
#define RULE_DEV_MAX_ACTION_LEN							UCHAR_MAX_LEN
#define RULE_DEV_MAX_LEN								(RULE_DEV_MAX_RULE_NAME_LEN + \
														 RULE_DEV_MAX_DIRECTION_LEN + \
														 RULE_DEV_MAX_SRC_IP_LEN + \
														 RULE_DEV_MAX_SRC_PREFIX_MASK_LEN + \
														 RULE_DEV_MAX_SRC_PREFIX_SIZE_LEN + \
														 RULE_DEV_MAX_DST_IP_LEN + \
														 RULE_DEV_MAX_DST_PREFIX_MASK_LEN + \
														 RULE_DEV_MAX_DST_PREFIX_SIZE_LEN + \
														 RULE_DEV_MAX_SRC_PORT_LEN + \
														 RULE_DEV_MAX_DST_PORT_LEN + \
														 RULE_DEV_MAX_PROTOCOL_LEN + \
														 RULE_DEV_MAX_ACK_LEN + \
														 RULE_DEV_MAX_ACTION_LEN + \
														 SEPERATORS_IN_RULE_DEV)

/* Rule Dev Min Format Length */				
#define RULE_DEV_MIN_RULE_NAME_LEN						(RULE_MIN_NAME_LENGTH+1)
#define RULE_DEV_MIN_DIRECTION_LEN						NUMERIC_MIN_LEN
#define RULE_DEV_MIN_SRC_IP_LEN							NUMERIC_MIN_LEN
#define RULE_DEV_MIN_SRC_PREFIX_MASK_LEN				NUMERIC_MIN_LEN
#define RULE_DEV_MIN_SRC_PREFIX_SIZE_LEN				NUMERIC_MIN_LEN
#define RULE_DEV_MIN_DST_IP_LEN							NUMERIC_MIN_LEN
#define RULE_DEV_MIN_DST_PREFIX_MASK_LEN				NUMERIC_MIN_LEN
#define RULE_DEV_MIN_DST_PREFIX_SIZE_LEN				NUMERIC_MIN_LEN
#define RULE_DEV_MIN_SRC_PORT_LEN						NUMERIC_MIN_LEN
#define RULE_DEV_MIN_DST_PORT_LEN						NUMERIC_MIN_LEN
#define RULE_DEV_MIN_PROTOCOL_LEN						NUMERIC_MIN_LEN
#define RULE_DEV_MIN_ACK_LEN							NUMERIC_MIN_LEN
#define RULE_DEV_MIN_ACTION_LEN							NUMERIC_MIN_LEN
#define RULE_DEV_MIN_LEN								(RULE_DEV_MIN_RULE_NAME_LEN + \
														 RULE_DEV_MIN_DIRECTION_LEN + \
														 RULE_DEV_MIN_SRC_IP_LEN + \
														 RULE_DEV_MIN_SRC_PREFIX_MASK_LEN + \
														 RULE_DEV_MIN_SRC_PREFIX_SIZE_LEN + \
														 RULE_DEV_MIN_DST_IP_LEN + \
														 RULE_DEV_MIN_DST_PREFIX_MASK_LEN + \
														 RULE_DEV_MIN_DST_PREFIX_SIZE_LEN + \
														 RULE_DEV_MIN_SRC_PORT_LEN + \
														 RULE_DEV_MIN_DST_PORT_LEN + \
														 RULE_DEV_MIN_PROTOCOL_LEN + \
														 RULE_DEV_MIN_ACK_LEN + \
														 RULE_DEV_MIN_ACTION_LEN + \
														 SEPERATORS_IN_RULE_DEV)

#define ALL_RULES_DEV_MAX_LEN							(RULE_DEV_MAX_LEN * MAX_RULES + 1)

/* End of Rule Defines Region */

/* Rules Sysfs communication Section */
#define RULES_ACTIVE_STATUS_LENGTH						1
#ifdef USER_MODE
	#define RULES_ACTIVE_STATUS_CODE					"1"
	#define RULES_INACTIVE_STATUS_CODE					"0"
#else
	#define RULES_ACTIVE_STATUS_CODE					'1'
	#define RULES_INACTIVE_STATUS_CODE					'0'
#endif

#define CLEAR_RULES_LENGTH								1
#define	CLEAR_RULES_CODE								'0'

#define RULES_MAX_NUMBER								MAX_RULES
#define RULES_MAX_NUMBER_LENGTH							2 	/* sizeof(MAX_RULES) == 2 */

typedef struct {
	char 			rule_name[20];		// names will be no longer than 20 chars
	int 			direction;
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
	int				ack; 				// values from: ack_t
	unsigned char	action;   			// valid values: NF_ACCEPT, NF_DROP
} rule_raw_t;

#endif
