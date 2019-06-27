#ifndef _CONNECTION_TABLE_DEV_H_
#define _CONNECTION_TABLE_DEV_H_

#ifdef USER_MODE
#include "user_sysfs_dev.h"
#else
#include "sysfs_dev.h"
#endif

/* Connection Talbe Device Section */
#define FW_DEVICE_NAME_CONNECTION_TABLE								"conn_tab"
#define DEVICE_CONNECTION_TABLE_ACTION_CONNECTION_TABLE_SIZE        "conn_tab_size"
#define CONNECTION_TABLE_DEVICE 									DEVICE_PREFIX FW_DEVICE_NAME_CONNECTION_TABLE

/* Connection Talbe Sysfs Section */
#define SYSFS_CONNECTION_TABLE_PATH									SYSFS_PATH_PREFIX CLASS_NAME "/" FW_DEVICE_NAME_CONNECTION_TABLE "/"
#define SYSFS_CONNECTION_TABLE_ATTRIBUTE_CONNECTION_TABLE_SIZE_PATH SYSFS_CONNECTION_TABLE_PATH DEVICE_CONNECTION_TABLE_ACTION_CONNECTION_TABLE_SIZE


/* Connection Talbe Sysfs communication Section */
/* User Actions */
#ifndef USER_ACTIONS_FIREWALL
#define USER_ACTIONS_FIREWALL
#define	SHOW_CONNECTION_TABLE							            "show_connection_table"
#endif          

/* Begin of Connection Table Defines Region */          

/* Connection Table Dev Format */           
#define	CONNECTION_TABLE_DEV_ITEM_SEPERATOR				            "\n"
#define	CONNECTION_TABLE_DEV_FIELD_SEPERATOR			            " "

#define FIELDS_IN_CONNECTION_TABLE_DEV					            8
#define SEPERATORS_IN_CONNECTION_TABLE_DEV				            9 /* strlen(FIELDS_IN_CONNECTION_TABLE_DEV*CONNECTION_TABLE_DEV_FIELD_SEPERATOR + CONNECTION_TABLE_DEV_ITEM_SEPERATOR) */

#define CONNECTION_TABLE_DEV_FORMAT						            (UINT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             USHRT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
                                                                     UINT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             USHRT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             CHAR_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             UINT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             UINT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             ULONG_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             CONNECTION_TABLE_DEV_ITEM_SEPERATOR)

#define NEW_CONNECTION_DEV_FORMAT						            (UINT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             USHRT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
                                                                     UINT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             USHRT_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             CHAR_FORMAT CONNECTION_TABLE_DEV_FIELD_SEPERATOR \
														             CONNECTION_TABLE_DEV_ITEM_SEPERATOR)

/* Connection Table Dev Max Format Length */	
#define CONNECTION_TABLE_DEV_MAX_SRC_IP_LEN							UINT_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_SRC_PORT_LEN						USHRT_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_DST_IP_LEN							UINT_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_DST_PORT_LEN						USHRT_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_PROTOCOL_LEN 						UCHAR_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_INITIATOR_STATE_LEN				UINT_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_RESPONDER_STATE_LEN				UINT_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_TIMESTAMP_LEN						ULONG_MAX_LEN
#define CONNECTION_TABLE_DEV_MAX_LEN								(CONNECTION_TABLE_DEV_MAX_SRC_IP_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_SRC_PORT_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_DST_IP_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_DST_PORT_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_PROTOCOL_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_INITIATOR_STATE_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_RESPONDER_STATE_LEN + \
                                                                     CONNECTION_TABLE_DEV_MAX_TIMESTAMP_LEN + \
                                                                     SEPERATORS_IN_CONNECTION_TABLE_DEV)

/* Connection Table Dev Min Format Length */	
#define CONNECTION_TABLE_DEV_MIN_SRC_IP_LEN							NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_SRC_PORT_LEN						NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_DST_IP_LEN							NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_DST_PORT_LEN						NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_PROTOCOL_LEN 						NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_INITIATOR_STATE_LEN				NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_RESPONDER_STATE_LEN				NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_TIMESTAMP_LEN						NUMERIC_MIN_LEN
#define CONNECTION_TABLE_DEV_MIN_LEN				                (CONNECTION_TABLE_DEV_MIN_SRC_IP_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_SRC_PORT_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_DST_IP_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_DST_PORT_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_PROTOCOL_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_INITIATOR_STATE_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_RESPONDER_STATE_LEN + \
                                                                     CONNECTION_TABLE_DEV_MIN_TIMESTAMP_LEN + \
                                                                     SEPERATORS_IN_CONNECTION_TABLE_DEV)

/* End of Connection Table Defines Region */

// connection
typedef struct { 
	unsigned int	    src_ip;		  	
	unsigned short	    src_port;	  	

	unsigned int	    dst_ip;	
	unsigned short	    dst_port;

    unsigned char       protocol;

    unsigned int        initiator_state;
    unsigned int        responder_state;

    unsigned long 		time_added;
} connection_row_raw_t;

#endif
