#ifndef _LOG_DEV_H_
#define _LOG_DEV_H_

#ifdef USER_MODE
#include "user_sysfs_dev.h"
#else
#include "sysfs_dev.h"
#endif

/* Log Device Section */
#define FW_DEVICE_NAME_LOG								"fw_log"
#define DEVICE_LOG_ACTION_LOG_SIZE						"log_size"
#define DEVICE_LOG_ACTION_LOG_CLEAR						"log_clear"
#define LOG_DEVICE 										DEVICE_PREFIX FW_DEVICE_NAME_LOG

/* Logs Sysfs Section */
#define SYSFS_LOG_PATH									SYSFS_PATH_PREFIX CLASS_NAME "/" FW_DEVICE_NAME_LOG "/"
#define SYSFS_LOG_ATTRIBUTE_LOG_SIZE_PATH				SYSFS_LOG_PATH DEVICE_LOG_ACTION_LOG_SIZE
#define SYSFS_LOG_ATTRIBUTE_LOG_CLEAR_PATH				SYSFS_LOG_PATH DEVICE_LOG_ACTION_LOG_CLEAR

/* Log Sysfs communication Section */
/* User Actions */
#ifndef USER_ACTIONS_LOG
#define USER_ACTIONS_LOG
#define	SHOW_LOG_ACTION									"show_log"
#define	CLEAR_LOG_ACTION								"clear_log"
#endif

/* Begin of Log Defines Region */

/* Log Prefrences */
#define LOG_OUTER_PACKETS								0

/* Log Dev Format */
#define	LOG_DEV_ITEM_SEPERATOR							"\n"
#define	LOG_DEV_FIELD_SEPERATOR							" "

#define FIELDS_IN_LOG_DEV								10
#define SEPERATORS_IN_LOG_DEV							11 /* strlen(FIELDS_IN_LOG_DEV*LOG_DEV_FIELD_SEPERATOR + LOG_DEV_ITEM_SEPERATOR) */

#define LOG_DEV_FORMAT									(ULONG_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 UCHAR_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 USHRT_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 USHRT_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 DECIMAL_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 UINT_FORMAT LOG_DEV_FIELD_SEPERATOR \
														 LOG_DEV_ITEM_SEPERATOR)

/* Log Dev Max Format Length */	
#define LOG_DEV_MAX_TIMESTAMP_LEN						ULONG_MAX_LEN
#define LOG_DEV_MAX_PROTOCOL_LEN 						UCHAR_MAX_LEN
#define LOG_DEV_MAX_ACTION_LEN   						UCHAR_MAX_LEN
#define LOG_DEV_MAX_HOOKNUM_LEN  						UCHAR_MAX_LEN
#define LOG_DEV_MAX_SRC_IP_LEN							UINT_MAX_LEN
#define LOG_DEV_MAX_DST_IP_LEN							UINT_MAX_LEN
#define LOG_DEV_MAX_SRC_PORT_LEN						USHRT_MAX_LEN
#define LOG_DEV_MAX_DST_PORT_LEN						USHRT_MAX_LEN
#define LOG_DEV_MAX_REASON_LEN   						UCHAR_MAX_LEN
#define LOG_DEV_MAX_COUNT_LEN    						UINT_MAX_LEN
#define LOG_DEV_MAX_LEN									(LOG_DEV_MAX_TIMESTAMP_LEN + \
														 LOG_DEV_MAX_PROTOCOL_LEN + \
                                        				 LOG_DEV_MAX_ACTION_LEN + \
                                        				 LOG_DEV_MAX_HOOKNUM_LEN + \
                                        				 LOG_DEV_MAX_SRC_IP_LEN + \
                                        				 LOG_DEV_MAX_DST_IP_LEN + \
                                        				 LOG_DEV_MAX_SRC_PORT_LEN + \
                                        				 LOG_DEV_MAX_DST_PORT_LEN + \
                                        				 LOG_DEV_MAX_REASON_LEN + \
                                        				 LOG_DEV_MAX_COUNT_LEN + \
														 SEPERATORS_IN_LOG_DEV)

/* Log Dev Min Format Length */	
#define LOG_DEV_MIN_TIMESTAMP_LEN						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_PROTOCOL_LEN 						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_ACTION_LEN   						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_HOOKNUM_LEN  						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_SRC_IP_LEN							NUMERIC_MIN_LEN
#define LOG_DEV_MIN_DST_IP_LEN							NUMERIC_MIN_LEN
#define LOG_DEV_MIN_SRC_PORT_LEN						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_DST_PORT_LEN						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_REASON_LEN   						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_COUNT_LEN    						NUMERIC_MIN_LEN
#define LOG_DEV_MIN_LEN									(LOG_DEV_MIN_TIMESTAMP_LEN + \
														 LOG_DEV_MIN_PROTOCOL_LEN + \
                                        				 LOG_DEV_MIN_ACTION_LEN + \
                                        				 LOG_DEV_MIN_HOOKNUM_LEN + \
                                        				 LOG_DEV_MIN_SRC_IP_LEN + \
                                        				 LOG_DEV_MIN_DST_IP_LEN + \
                                        				 LOG_DEV_MIN_SRC_PORT_LEN + \
                                        				 LOG_DEV_MIN_DST_PORT_LEN + \
                                        				 LOG_DEV_MIN_REASON_LEN + \
                                        				 LOG_DEV_MIN_COUNT_LEN + \
														 SEPERATORS_IN_LOG_DEV)

/* End of Log Defines Region */

#define CLEAR_LOG_LENGTH								1
#define	CLEAR_LOG_CODE									'0'

// logging
typedef struct {
	unsigned long  	timestamp;     	// time of creation/update
	unsigned char  	protocol;     	// values from: prot_t
	unsigned char  	action;       	// valid values: NF_ACCEPT, NF_DROP
	unsigned char  	hooknum;      	// as received from netfilter hook
	unsigned int	src_ip;		  	
	unsigned int	dst_ip;		  	
	unsigned short	src_port;	  	
	unsigned short	dst_port;	  	
	int     		reason;       	// rule#index, or values from: reason_t
	unsigned int   	count;        	// counts this line's hits
} log_row_raw_t;

#endif
