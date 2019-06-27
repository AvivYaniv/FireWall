#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <netinet/in.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include "bool.h"
#include "debug.h"
#include "user_fw.h"
#include "rules_dev.h"
#include "connection_dev.h"
#include "log_dev.h"

#ifdef PRINT_DEBUG_MESSAGES
#include <errno.h>
#endif

/* User Actions */
#define USER_ACTION_ARG_INDEX							1
#define RULES_FILE_ARG_INDEX							2
#define USER_ACTION_MAX_LENGTH							12 /* strlen(CLEAR_RULES_ACTION) */

#ifndef USER_ACTIONS_RULES
#define USER_ACTIONS_RULES
#define	ACTIVATE_ACTION									"activate"
#define	DEACTIVATE_ACTION								"deactivate"
#define	SHOW_RULES_ACTION								"show_rules"
#define	CLEAR_RULES_ACTION								"clear_rules"
#define	LOAD_RULES_ACTION								"load_rules"
#endif

#ifndef USER_ACTIONS_FIREWALL
#define USER_ACTIONS_FIREWALL
#define	SHOW_CONNECTION_TABLE							 "show_connection_table"
#endif    

#ifndef USER_ACTIONS_LOG
#define USER_ACTIONS_LOG
#define	SHOW_LOG_ACTION									"show_log"
#define	CLEAR_LOG_ACTION								"clear_log"
#endif

/* Printing Format */	
#define PRINT_SEPERATOR									" "					
#define RULE_PRINTING_FORMAT							"%s %s %s %s %s %s %s %s %s\n"
#define LOG_PRINTING_FORMAT								(ULONG_FORMAT PRINT_SEPERATOR \
									 					 STRING_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 UCHAR_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 DECIMAL_FORMAT PRINT_SEPERATOR \
														 UINT_FORMAT PRINT_SEPERATOR \
														 "\n")
#define CONNECTION_PRINTING_FORMAT						(STRING_FORMAT PRINT_SEPERATOR \
														 USHRT_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 USHRT_FORMAT PRINT_SEPERATOR \
														 STRING_FORMAT PRINT_SEPERATOR \
														 UINT_FORMAT PRINT_SEPERATOR \
														 UINT_FORMAT PRINT_SEPERATOR \
														 ULONG_FORMAT PRINT_SEPERATOR \
														 "\n")

/* Enum Section */
#define FOREACH_RETURN_VALUE(RETURN_VALUE) \
			RETURN_VALUE(SUCCESS) \
			RETURN_VALUE(NO_MEMORY_ERROR) \
			RETURN_VALUE(FAILED_OPEN_SYSFS_RULES_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_READ_SYSFS_RULES_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_WRITE_SYSFS_RULES_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_OPEN_SYSFS_LOG_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_READ_SYSFS_LOG_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_WRITE_SYSFS_LOG_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_OPEN_SYSFS_CONNECTION_TABLE_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_READ_SYSFS_CONNECTION_TABLE_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_WRITE_SYSFS_CONNECTION_TABLE_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_OPEN_RULES_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_READ_RULES_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_WRITE_RULES_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_OPEN_LOG_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_READ_LOG_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_WRITE_LOG_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_OPEN_CONNECTION_TABLE_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_READ_CONNECTION_TABLE_DEVICE_ERROR) \
			RETURN_VALUE(FAILED_WRITE_CONNECTION_TABLE_DEVICE_ERROR) \
			RETURN_VALUE(USER_ACTION_IS_INVALID_ERROR) \
			RETURN_VALUE(RULE_PATH_IS_NOT_FILE_ERROR) \
			RETURN_VALUE(FAILED_OPEN_RULES_FILE_ERROR) \
			RETURN_VALUE(FAILED_PARSE_RULE_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_RULE_FIELD_TO_STRING_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_RULES_SIZE_TO_STRING_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_LOG_SIZE_TO_STRING_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_LOG_ROW_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_LOG_FIELD_TO_STRING_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_CONNECTION_TABLE_SIZE_TO_STRING_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_CONNECTION_TABLE_ROW_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(FAILED_PARSE_CONNECTION_TABLE_FIELD_TO_STRING_FROM_FIREWALL_ERROR) \
			RETURN_VALUE(RULE_CONVERTION_TO_DEV_FRMT_FAILED_ERROR) \
			RETURN_VALUE(RULE_STATUS_PARSING_FAILED_ERROR) \
			RETURN_VALUE(LOG_PARSING_FAILED_ERROR) \
			RETURN_VALUE(RETURN_VALUE_NUMBER) \

#define GENERATE_ENUM(ENUM) 	ENUM,
#define GENERATE_STRING(STRING) #STRING,

typedef enum EReturnValue {
	FOREACH_RETURN_VALUE(GENERATE_ENUM)
} EReturnValue;

#ifdef PRINT_DEBUG_MESSAGES
	static const char* RETURN_VALUE_STRING[] = {
		FOREACH_RETURN_VALUE(GENERATE_STRING)
	};
#endif

/* Methods Section */
EReturnValue getRulesActiveStatus(BOOL* pbIsActive)
{
	/* Varaible Section */
	int fdFirewallRulesSysfs;
	ssize_t stBytesRead;
	char arrActiveStatus[RULES_ACTIVE_STATUS_LENGTH + 1];
	
	/* Code Section */
	/* Opening firewall rules device sysfs */
	fdFirewallRulesSysfs = open(SYSFS_RULES_ATTRIBUTE_ACTIVATE_PATH, O_RDONLY);
	
	/* Validate openning firewall rules device sysfs */
	if (0 > fdFirewallRulesSysfs)
	{
		/* Return error */
		return FAILED_OPEN_SYSFS_RULES_DEVICE_ERROR;
	}
	/* Else, firewall sysfs opened successfully */
	else
	{
		/* Read firewall rules device sysfs */
		/* Read file */
		stBytesRead = 0;

		/* Reading from firewall rules device sysfs */
		stBytesRead = read(fdFirewallRulesSysfs, arrActiveStatus, RULES_ACTIVE_STATUS_LENGTH);

		/* Ending string */
		arrActiveStatus[stBytesRead]='\0';

		/* Closing firewall rules device sysfs */
		close(fdFirewallRulesSysfs);

		/* Checking error value */
		if (0 > stBytesRead)
		{
			/* Return error */
			return FAILED_READ_SYSFS_RULES_DEVICE_ERROR;
		}

		/* If status is active */
		if (!strncmp(
				arrActiveStatus, 
				RULES_ACTIVE_STATUS_CODE, 
				RULES_ACTIVE_STATUS_LENGTH))
		{
			*pbIsActive = TRUE;
		}
		/* Else if, status is inactive */
		else if (!strncmp(
					arrActiveStatus, 
					RULES_INACTIVE_STATUS_CODE, 
					RULES_ACTIVE_STATUS_LENGTH))
		{
			*pbIsActive = FALSE;
		}
		/* Else, failed parse status */	
		{
			return RULE_STATUS_PARSING_FAILED_ERROR;
		}
		
		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_SYSFS_RULES_DEVICE_ERROR;
}

EReturnValue setRulesActiveStatus(BOOL bIsActive)
{
	/* Varaible Section */
	int fdFirewallRulesSysfs;
	ssize_t stBytesWritten;
	char arrActiveStatus[RULES_ACTIVE_STATUS_LENGTH + 1];
	
	/* Code Section */
	/* Copying active status to write */
	strncpy(arrActiveStatus, 
			(bIsActive ? RULES_ACTIVE_STATUS_CODE : RULES_INACTIVE_STATUS_CODE), 
			RULES_ACTIVE_STATUS_LENGTH);

	/* As matter of security, null-terminating the string */
	arrActiveStatus[RULES_ACTIVE_STATUS_LENGTH] = '\0';

	/* Opening firewall rules device sysfs */
	fdFirewallRulesSysfs = open(SYSFS_RULES_ATTRIBUTE_ACTIVATE_PATH, O_WRONLY);
	
	/* Validate opening firewall rules device sysfs */
	if (0 > fdFirewallRulesSysfs)
	{
		/* Return error */
		return FAILED_OPEN_SYSFS_RULES_DEVICE_ERROR;
	}
	/* Else, firewall rules device sysfs opened successfully */
	else
	{
		/* Writing user code to firewall rules device sysfs */
		stBytesWritten = 
			write(fdFirewallRulesSysfs, 
				  arrActiveStatus, 
				  RULES_ACTIVE_STATUS_LENGTH);

		/* Closing firewall rules device sysfs */
		close(fdFirewallRulesSysfs);
		
		/* Validating written succesfully */
		if (strlen(arrActiveStatus) != stBytesWritten)
		{
			/* Return error */
			return FAILED_WRITE_SYSFS_RULES_DEVICE_ERROR;
		}
		
		/* Return success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_WRITE_SYSFS_RULES_DEVICE_ERROR;
}

EReturnValue writeRulesToFirewall(char* strRules)
{
	/* Varaible Section */
	int fdFirewallRulesDevice;
	ssize_t stBytesWritten;
	ssize_t stRulesLength = strlen(strRules);
	
	/* Code Section */	
	/* Opening firewall rules device */
	fdFirewallRulesDevice = open(RULES_DEVICE, O_WRONLY);
	
	/* Validate opening firewall rules device */
	if (0 > fdFirewallRulesDevice)
	{
		/* Return error */
		return FAILED_OPEN_RULES_DEVICE_ERROR;
	}
	/* Else, firewall rules device opened successfully */
	else
	{
		/* Writing user code to firewall rules device */
		stBytesWritten = 
			write(fdFirewallRulesDevice, 
				  strRules, 
				  stRulesLength);

		/* Closing firewall rules device */
		close(fdFirewallRulesDevice);
		
		/* Validating written succesfully */
		if (stRulesLength != stBytesWritten)
		{
			/* Return error */
			return FAILED_WRITE_RULES_DEVICE_ERROR;
		}
		
		/* Return success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_WRITE_RULES_DEVICE_ERROR;
}

EReturnValue getRulesSize(unsigned int* pSize)
{
	/* Varaible Section */
	int fdFirewallRulesSysfs;
	ssize_t stBytesRead;
	char arrSize[UINT_MAX_LEN + 1];
	
	/* Code Section */
	/* Opening firewall rules device sysfs */
	fdFirewallRulesSysfs = open(SYSFS_RULES_ATTRIBUTE_RULES_SIZE_PATH, O_RDONLY);
	
	/* Validate openning firewall rules sysfs */
	if (0 > fdFirewallRulesSysfs)
	{
		/* Return error */
		return FAILED_OPEN_SYSFS_RULES_DEVICE_ERROR;
	}
	/* Else, firewall sysfs opened successfully */
	else
	{
		/* Read firewall rules device sysfs */
		/* Read file */
		stBytesRead = 0;

		/* Reading from firewall rules device sysfs */
		stBytesRead = read(fdFirewallRulesSysfs, arrSize, UINT_MAX_LEN);

		/* Ending string */
		arrSize[stBytesRead]='\0';

		/* Closing firewall rules device sysfs */
		close(fdFirewallRulesSysfs);

		/* Checking error value */
		if (0 > stBytesRead)
		{
			/* Return error */
			return FAILED_READ_SYSFS_RULES_DEVICE_ERROR;
		}

		/* If failed to translate to size */
		if (1 != sscanf(arrSize, UINT_FORMAT, pSize))
		{
			return FAILED_PARSE_RULES_SIZE_TO_STRING_FROM_FIREWALL_ERROR;
		}
		
		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_SYSFS_LOG_DEVICE_ERROR;
}

EReturnValue readRulesFromFirewall(char** pRulesDevFormat)
{
	/* Varaible Section */
	int fdFirewallRulesSysfs;
	ssize_t stBytesRead;
	ssize_t stTotalBytesRead;
	ssize_t stMaxToRead;
	EReturnValue rvReturnValue;
	unsigned int uSize;
	char* strRulesDevFormat;
			
	/* Code Section */
	/* Getting rules size */
	if (SUCCESS != (rvReturnValue = getRulesSize(&uSize)))
	{
		/* Return failure */
		return rvReturnValue;
	}

	stMaxToRead = RULE_DEV_MAX_LEN * uSize;
	*pRulesDevFormat = (char*)calloc(stMaxToRead, sizeof(char));

	/* Validating memory allocation */
	if (!*pRulesDevFormat)
	{
		return NO_MEMORY_ERROR;
	}

	strRulesDevFormat = *pRulesDevFormat;

	/* Opening firewall rules device sysfs */
	fdFirewallRulesSysfs = open(RULES_DEVICE, O_RDONLY);
	
	/* Validate openning firewall rules device sysfs */
	if (0 > fdFirewallRulesSysfs)
	{
		/* Return error */
		return FAILED_OPEN_RULES_DEVICE_ERROR;
	}
	/* Else, firewall sysfs opened successfully */
	else
	{
		/* Read firewall rules device sysfs */
		/* Read file */
		stBytesRead = 0;
		stTotalBytesRead = 0;

		/* Reading from firewall rules device sysfs */
		while ((0 < (stBytesRead = 
						read(fdFirewallRulesSysfs, 
							 strRulesDevFormat + stTotalBytesRead, 
							 RULE_DEV_MAX_LEN))) && 
				(stTotalBytesRead < stMaxToRead))
		{
			stTotalBytesRead += stBytesRead;
		}

		/* Ending string */
		strRulesDevFormat[stTotalBytesRead]='\0';

		/* Closing firewall rules device sysfs */
		close(fdFirewallRulesSysfs);

		/* Checking error value */
		if (0 > stBytesRead)
		{	
			/* Free rules string */
			if (strRulesDevFormat) 
			{
				free(strRulesDevFormat);
			}

			/* Return error */
			return FAILED_READ_RULES_DEVICE_ERROR;
		}

		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_RULES_DEVICE_ERROR;
}

EReturnValue getLogSize(unsigned int* pSize)
{
	/* Varaible Section */
	int fdFirewallLogSysfs;
	ssize_t stBytesRead;
	char arrSize[UINT_MAX_LEN + 1];
	
	/* Code Section */
	/* Opening firewall log device sysfs */
	fdFirewallLogSysfs = open(SYSFS_LOG_ATTRIBUTE_LOG_SIZE_PATH, O_RDONLY);
	
	/* Validate openning firewall rules log sysfs */
	if (0 > fdFirewallLogSysfs)
	{
		/* Return error */
		return FAILED_OPEN_SYSFS_LOG_DEVICE_ERROR;
	}
	/* Else, firewall sysfs opened successfully */
	else
	{
		/* Read firewall log device sysfs */
		/* Read file */
		stBytesRead = 0;

		/* Reading from firewall log device sysfs */
		stBytesRead = read(fdFirewallLogSysfs, arrSize, UINT_MAX_LEN);

		/* Ending string */
		arrSize[stBytesRead]='\0';

		/* Closing firewall log device sysfs */
		close(fdFirewallLogSysfs);

		/* Checking error value */
		if (0 > stBytesRead)
		{
			/* Return error */
			return FAILED_READ_SYSFS_LOG_DEVICE_ERROR;
		}

		/* If failed to translate to size */
		if (1 != sscanf(arrSize, UINT_FORMAT, pSize))
		{
			return FAILED_PARSE_LOG_SIZE_TO_STRING_FROM_FIREWALL_ERROR;
		}
		
		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_SYSFS_LOG_DEVICE_ERROR;
}

EReturnValue readLogsFromFirewall(char** pLogsDevFormat, unsigned int* pSize)
{
	/* Varaible Section */
	int fdFirewallLogsDevice;	
	ssize_t stBytesRead;
	ssize_t stTotalBytesRead;
	ssize_t stMaxToRead;
	EReturnValue rvReturnValue;
	
	/* Code Section */
	/* Getting log size */
	if (SUCCESS != (rvReturnValue = getLogSize(pSize)))
	{
		/* Return failure */
		return rvReturnValue;
	}
	
	stMaxToRead = LOG_DEV_MAX_LEN * (*pSize);
	*pLogsDevFormat = (char*)calloc(stMaxToRead, sizeof(char));

	/* Validating memory allocation */
	if (!*pLogsDevFormat)
	{
		return NO_MEMORY_ERROR;
	}

	/* Opening firewall log device */
	fdFirewallLogsDevice = open(LOG_DEVICE, O_RDONLY);
	
	/* Validate openning firewall log device */
	if (0 > fdFirewallLogsDevice)
	{
		/* Return error */
		return FAILED_OPEN_LOG_DEVICE_ERROR;
	}
	/* Else, firewall device opened successfully */
	else
	{
		/* Read firewall log device */
		/* Read file */
		stBytesRead = 0;
		stTotalBytesRead = 0;

		/* Reading from firewall log device */
		while ((0 < (stBytesRead = 
						read(fdFirewallLogsDevice, 
							 (*pLogsDevFormat) + stTotalBytesRead, 
							 LOG_DEV_MAX_LEN))) && 
				(stTotalBytesRead < stMaxToRead))
		{
			stTotalBytesRead += stBytesRead;
		}

		/* Ending string */
		(*pLogsDevFormat)[stTotalBytesRead]='\0';

		/* Closing firewall log device */
		close(fdFirewallLogsDevice);

		/* Checking error value */
		if (0 > stBytesRead)
		{
			/* Free logs string */
			if (*pLogsDevFormat) 
			{
				free(*pLogsDevFormat);
			}

			/* Return error */
			return FAILED_READ_LOG_DEVICE_ERROR;
		}
		
		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_LOG_DEVICE_ERROR;
}

EReturnValue getConnectionTableSize(unsigned int* pSize)
{
	/* Varaible Section */
	int fdFirewallConnectionTableSysfs;
	ssize_t stBytesRead;
	char arrSize[UINT_MAX_LEN + 1];
	
	/* Code Section */
	/* Opening firewall connection table device sysfs */
	fdFirewallConnectionTableSysfs = open(SYSFS_CONNECTION_TABLE_ATTRIBUTE_CONNECTION_TABLE_SIZE_PATH, O_RDONLY);
	
	/* Validate openning firewall rules connection table sysfs */
	if (0 > fdFirewallConnectionTableSysfs)
	{
		/* Return error */
		return FAILED_OPEN_SYSFS_CONNECTION_TABLE_DEVICE_ERROR;
	}
	/* Else, firewall sysfs opened successfully */
	else
	{
		/* Read firewall connection table device sysfs */
		/* Read file */
		stBytesRead = 0;

		/* Reading from firewall connection table device sysfs */
		stBytesRead = read(fdFirewallConnectionTableSysfs, arrSize, UINT_MAX_LEN);

		/* Ending string */
		arrSize[stBytesRead]='\0';

		/* Closing firewall connection table device sysfs */
		close(fdFirewallConnectionTableSysfs);

		/* Checking error value */
		if (0 > stBytesRead)
		{
			/* Return error */
			return FAILED_READ_SYSFS_CONNECTION_TABLE_DEVICE_ERROR;
		}

		/* If failed to translate to size */
		if (1 != sscanf(arrSize, UINT_FORMAT, pSize))
		{
			return FAILED_PARSE_CONNECTION_TABLE_SIZE_TO_STRING_FROM_FIREWALL_ERROR;
		}
		
		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_SYSFS_CONNECTION_TABLE_DEVICE_ERROR;
}

EReturnValue readConnectionTablesFromFirewall(char** pConnectionTablesDevFormat, unsigned int* pSize)
{
	/* Varaible Section */
	int fdFirewallConnectionTablesDevice;	
	ssize_t stBytesRead;
	ssize_t stTotalBytesRead;
	ssize_t stMaxToRead;
	EReturnValue rvReturnValue;
	
	/* Code Section */
	/* Getting connection table size */
	if (SUCCESS != (rvReturnValue = getConnectionTableSize(pSize)))
	{
		/* Return failure */
		return rvReturnValue;
	}
	
	stMaxToRead = CONNECTION_TABLE_DEV_MAX_LEN * (*pSize);
	*pConnectionTablesDevFormat = (char*)calloc(stMaxToRead, sizeof(char));

	/* Validating memory allocation */
	if (!*pConnectionTablesDevFormat)
	{
		return NO_MEMORY_ERROR;
	}

	/* Opening firewall connection table device */
	fdFirewallConnectionTablesDevice = open(CONNECTION_TABLE_DEVICE, O_RDONLY);
	
	/* Validate openning firewall connection table device */
	if (0 > fdFirewallConnectionTablesDevice)
	{
		/* Return error */
		return FAILED_OPEN_CONNECTION_TABLE_DEVICE_ERROR;
	}
	/* Else, firewall device opened successfully */
	else
	{
		/* Read firewall connection table device */
		/* Read file */
		stBytesRead = 0;
		stTotalBytesRead = 0;

		/* Reading from firewall connection table device */
		while ((0 < (stBytesRead = 
						read(fdFirewallConnectionTablesDevice, 
							 (*pConnectionTablesDevFormat) + stTotalBytesRead, 
							 CONNECTION_TABLE_DEV_MAX_LEN))) && 
				(stTotalBytesRead < stMaxToRead))
		{
			stTotalBytesRead += stBytesRead;
		}

		/* Ending string */
		(*pConnectionTablesDevFormat)[stTotalBytesRead]='\0';

		/* Closing firewall connection table device */
		close(fdFirewallConnectionTablesDevice);

		/* Checking error value */
		if (0 > stBytesRead)
		{
			/* Free connection tables string */
			if (*pConnectionTablesDevFormat) 
			{
				free(*pConnectionTablesDevFormat);
			}

			/* Return error */
			return FAILED_READ_CONNECTION_TABLE_DEVICE_ERROR;
		}
		
		/* Return Success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_READ_CONNECTION_TABLE_DEVICE_ERROR;
}

BOOL directionToString(direction_t direction, char strDirection[])
{
	/* Code Section */
	switch (direction)
	{
		case DIRECTION_IN:
		{
			strcpy(strDirection, "in");
			break;
		}

		case DIRECTION_OUT:
		{
			strcpy(strDirection, "out");
			break;
		}

		case DIRECTION_ANY:
		{
			strcpy(strDirection, "any");
			break;
		}

		default:
		{
			/* Return failure */
			return FALSE;

			break;
		}
	}

	/* Return Suceess */
	return TRUE;
}

/*
 * Based on: http://www.skyfree.org/linux/gatekeeper/ip.C
 */
BOOL IpToString(unsigned int ip, char strIP[], unsigned char mask)
{
	int a1, a2, a3, a4;
		
	a1 = ((ip & 0xFF000000) >> 24) & 255;
	a2 = (ip & 0x00FF0000) >> 16;
	a3 = (ip & 0x0000FF00) >> 8;
	a4 = (ip & 0x000000FF);

	/* All zeros */
	if (!(a1 || a2 || a3 || a4 || mask))
	{
		strcpy(strIP, "any");
	}
	else if (0 == mask)
	{
		sprintf(strIP, "%d.%d.%d.%d", a1, a2, a3, a4);
	}
	else
	{
		sprintf(strIP, "%d.%d.%d.%d/%hhu", a1, a2, a3, a4, mask);
	}

	return TRUE;
}

BOOL portToString(unsigned short port, char strPort[])
{
	/* Code Section */
	switch (port)
	{
		case PORT_ANY:
		{
			strcpy(strPort, "any");
			break;
		}

		case PORT_ABOVE_1023:
		{
			strcpy(strPort, ">1023");
			break;
		}

		default:
		{
			sprintf(strPort, USHRT_FORMAT, port);

			break;
		}
	}

	/* Return Suceess */
	return TRUE;
}

BOOL protocolToString(unsigned char protocol, char strProtocol[])
{
	/* Code Section */
	switch (protocol)
	{
		case PROT_ICMP:
		{
			strcpy(strProtocol, "icmp");
			break;
		}

		case PROT_TCP:
		{
			strcpy(strProtocol, "tcp");
			break;
		}

		case PROT_UDP:
		{
			strcpy(strProtocol, "udp");
			break;
		}

		case PROT_OTHER:
		{
			strcpy(strProtocol, "other");
			break;
		}

		case PROT_ANY:
		{
			strcpy(strProtocol, "any");
			break;
		}

		default:
		{
			/* Return Failure */
			return FALSE;
		}
	}

	/* Return Suceess */
	return TRUE;
}

BOOL ackToString(ack_t ack, char strAck[])
{
	/* Code Section */
	switch (ack)
	{
		case ACK_YES:
		{
			strcpy(strAck, "yes");
			break;
		}

		case ACK_NO:
		{
			strcpy(strAck, "no");
			break;
		}

		case ACK_ANY:
		{
			strcpy(strAck, "any");
			break;
		}

		default:
		{
			/* Return Failure */
			return FALSE;
		}
	}

	/* Return Suceess */
	return TRUE;
}

BOOL actionToString(unsigned char action, char strAction[])
{
	/* Code Section */
	switch (action)
	{
		case NF_ACCEPT:
		{
			strcpy(strAction, "accept");
			break;
		}

		case NF_DROP:
		{
			strcpy(strAction, "drop");
			break;
		}

		default:
		{
			/* Return Failure */
			return FALSE;
		}
	}

	/* Return Suceess */
	return TRUE;
}

EReturnValue printSingleDevRule(char* strSingleRuleDevFormat)
{
	/* Variable Definition */
	rule_raw_t 	tRule;
	int			nLength;
	char 		strDirection[DIRECTION_MAX_LENGTH+1];
	char 		strSrcIp[IP_MAX_LENGTH+1];
	char 		strDstIp[IP_MAX_LENGTH+1];
	char 		strSrcPort[PORT_MAX_LENGTH+1];
	char 		strDstPort[PORT_MAX_LENGTH+1];
	char 		strProtocol[PROTOCOL_MAX_LENGTH+1];
	char 		strAck[ACK_MAX_LENGTH+1];
	char 		strAction[ACTION_MAX_LENGTH+1];	

	/* Code Section */	
	nLength = strnlen(strSingleRuleDevFormat, RULE_DEV_MAX_LEN);

	/* If rules length is invalid */
	if (0 >= nLength)
	{
		return FAILED_PARSE_RULE_FROM_FIREWALL_ERROR;
	}

	/* Parsing firewall rule dev format to rule fields  */
	if (FIELDS_IN_RULE_DEV != 
		sscanf(strSingleRuleDevFormat, 
			   RULE_DEV_FORMAT, 
			   tRule.rule_name,
			   &tRule.direction,
			   &tRule.src_ip,
			   &tRule.src_prefix_mask,
			   &tRule.src_prefix_size,										
			   &tRule.dst_ip,
			   &tRule.dst_prefix_mask,
			   &tRule.dst_prefix_size,
			   &tRule.src_port,
			   &tRule.dst_port,
			   &tRule.protocol,
			   &tRule.ack,
			   &tRule.action))
	{
		return FAILED_PARSE_RULE_FROM_FIREWALL_ERROR;
	}

	/* Parsing rule fields to strings */	
	if (!directionToString((direction_t)tRule.direction, strDirection) ||
		!IpToString(tRule.src_ip, strSrcIp, tRule.src_prefix_size) || 
		!IpToString(tRule.dst_ip, strDstIp, tRule.dst_prefix_size) || 
		!portToString(tRule.src_port, strSrcPort) ||
		!portToString(tRule.dst_port, strDstPort) || 
		!protocolToString(tRule.protocol, strProtocol) ||
		!ackToString((ack_t)tRule.ack, strAck) ||
		!actionToString(tRule.action, strAction))
	{
		return FAILED_PARSE_RULE_FIELD_TO_STRING_FROM_FIREWALL_ERROR;
	}

	/* Printing rule on user screen */
	printf(RULE_PRINTING_FORMAT, 
		   tRule.rule_name,
		   strDirection,
		   strSrcIp,
		   strDstIp,
		   strProtocol,
		   strSrcPort,
		   strDstPort,
		   strAck,
		   strAction);
	
	/* Return Suceess */
	return SUCCESS;
}

EReturnValue printDevRules(char* strRulesDevFormat, const unsigned int uMaxRules)
{
	/* Variable Section */
	char* strSingleRuleDevFormat;
	EReturnValue rvReturnValue;

	/* Code Section */
	while ((NULL != 
		    (strSingleRuleDevFormat = 
		   		strsep(&strRulesDevFormat, 
				   	   RULE_DEV_ITEM_SEPERATOR))))
	{
		/* If rule to parse */
		if (0 < strnlen(strSingleRuleDevFormat, RULE_DEV_MAX_LEN))
		{
			rvReturnValue = printSingleDevRule(strSingleRuleDevFormat);
		
			if (SUCCESS != rvReturnValue)
			{
				return rvReturnValue;
			}
		}
	}

	return SUCCESS;
}

EReturnValue showRules()
{	
	/* Variable Definition */
	char* strRulesDevFormat = NULL;

	/* Code Section */
	/* Reading rules from firewall */
	EReturnValue rvReturnValue = readRulesFromFirewall(&strRulesDevFormat);

	/* If faild to read rules */
	if (SUCCESS != rvReturnValue)
	{
		/* Freeing rules from dev string */
		if (strRulesDevFormat)
		{
			free(strRulesDevFormat);
		}

		/* Return failure */
		return rvReturnValue;
	}

	/* Parsing rules to rules table */
	rvReturnValue = printDevRules(strRulesDevFormat, MAX_RULES);

	/* Freeing rules from dev string */
	if (strRulesDevFormat)
	{
		free(strRulesDevFormat);
	}
	
	/* Return */
	return rvReturnValue;
}

EReturnValue clearRules()
{
	/* Varaible Section */
	int fdFirewallRulesDevice;
	ssize_t stBytesWritten;
	char arrClearRules[CLEAR_RULES_LENGTH+1];
	
	/* Code Section */
	/* Setting the clear log code */
	arrClearRules[0] = CLEAR_RULES_CODE;

	/* As matter of security, null-terminating the string */
	arrClearRules[CLEAR_RULES_LENGTH] = '\0';

	/* Opening firewall rules device */
	fdFirewallRulesDevice = open(RULES_DEVICE, O_WRONLY);
	
	/* Validate opening firewall rules device */
	if (0 > fdFirewallRulesDevice)
	{
		/* Return error */
		return FAILED_OPEN_RULES_DEVICE_ERROR;
	}
	/* Else, firewall rules device opened successfully */
	else
	{
		/* Writing user code to firewall rules device */
		stBytesWritten = 
			write(fdFirewallRulesDevice, 
				  arrClearRules, 
				  CLEAR_RULES_LENGTH);

		/* Closing firewall rules device */
		close(fdFirewallRulesDevice);
		
		/* Validating written succesfully */
		if (CLEAR_RULES_LENGTH != stBytesWritten)
		{
			/* Return error */
			return FAILED_WRITE_RULES_DEVICE_ERROR;
		}
		
		/* Return success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_WRITE_RULES_DEVICE_ERROR;
}

EReturnValue printSingleDevConnection(char* strSingleConnectionDevFormat)
{
	/* Variable Definition */
	connection_row_raw_t tConnectionRow;
	char strSrcIp[IP_MAX_LENGTH-PREFIX_MAX_LENGTH+1];
	char strDstIp[IP_MAX_LENGTH-PREFIX_MAX_LENGTH+1];
	char strProtocol[PROTOCOL_MAX_LENGTH+1];

	/* Code Section */
	/* If nothing to print */
	if (0 == strlen(strSingleConnectionDevFormat))
	{
		return SUCCESS;
	}

	/* Parsing firewall connection dev format to connection fields  */
	if (FIELDS_IN_CONNECTION_TABLE_DEV !=  
		sscanf(strSingleConnectionDevFormat, 
			   CONNECTION_TABLE_DEV_FORMAT, 
			   &tConnectionRow.src_ip,
			   &tConnectionRow.src_port, 
			   &tConnectionRow.dst_ip,   
			   &tConnectionRow.dst_port,  
			   &tConnectionRow.protocol, 											
			   &tConnectionRow.initiator_state, 	
			   &tConnectionRow.responder_state, 
			   &tConnectionRow.time_added))
	{
		return FAILED_PARSE_CONNECTION_TABLE_ROW_FROM_FIREWALL_ERROR;
	}

	/* Parsing connection fields to strings */
	if (!protocolToString(tConnectionRow.protocol, strProtocol) ||
		!IpToString(tConnectionRow.src_ip, strSrcIp, 0) || 
		!IpToString(tConnectionRow.dst_ip, strDstIp, 0))
	{
		return FAILED_PARSE_CONNECTION_TABLE_FIELD_TO_STRING_FROM_FIREWALL_ERROR;
	}

	/* Printing connection on user screen */
	printf(CONNECTION_PRINTING_FORMAT, 
		   strSrcIp,
		   tConnectionRow.src_port,
		   strDstIp,
		   tConnectionRow.dst_port,
		   strProtocol,
		   tConnectionRow.initiator_state,
		   tConnectionRow.responder_state,
		   tConnectionRow.time_added);
	
	/* Return Suceess */
	return SUCCESS;
}

EReturnValue printDevConnectionTable(char* strConnectionTableDevFormat, const unsigned int uConnectionTableSize)
{
	/* Variable Section */
	char* strSingleConnectionDevFormat;
	EReturnValue rvReturnValue;

	/* Code Section */
	while ((NULL != 
		    (strSingleConnectionDevFormat = 
		   		strsep(&strConnectionTableDevFormat, 
				   	   CONNECTION_TABLE_DEV_ITEM_SEPERATOR))))
	{		
		rvReturnValue = printSingleDevConnection(strSingleConnectionDevFormat);
		
		if (SUCCESS != rvReturnValue)
		{
			return rvReturnValue;
		}
	}

	return SUCCESS;
}

EReturnValue printSingleDevLog(char* strSingleLogDevFormat)
{
	/* Variable Definition */
	log_row_raw_t tLogRow;
	char strProtocol[PROTOCOL_MAX_LENGTH+1];
	char strAction[ACTION_MAX_LENGTH+1];	 
	char strSrcIp[IP_MAX_LENGTH-PREFIX_MAX_LENGTH+1];
	char strDstIp[IP_MAX_LENGTH-PREFIX_MAX_LENGTH+1];
	char strSrcPort[PORT_MAX_LENGTH+1];
	char strDstPort[PORT_MAX_LENGTH+1]; 

	/* Code Section */
	/* If nothing to print */
	if (0 == strlen(strSingleLogDevFormat))
	{
		return SUCCESS;
	}

	/* Parsing firewall rule dev format to rule fields  */
	if (FIELDS_IN_LOG_DEV !=  
		sscanf(strSingleLogDevFormat, 
			   LOG_DEV_FORMAT, 
			   &tLogRow.timestamp,
			   &tLogRow.protocol, 
			   &tLogRow.action,   
			   &tLogRow.hooknum,  
			   &tLogRow.src_ip, 											
			   &tLogRow.dst_ip, 	
			   &tLogRow.src_port, 
			   &tLogRow.dst_port, 
			   &tLogRow.reason,   
			   &tLogRow.count))
	{
		return FAILED_PARSE_LOG_ROW_FROM_FIREWALL_ERROR;
	}

	/* Parsing log fields to strings */
	if (!protocolToString(tLogRow.protocol, strProtocol) ||
		!actionToString(tLogRow.action, strAction) ||
		!IpToString(tLogRow.src_ip, strSrcIp, 0) || 
		!IpToString(tLogRow.dst_ip, strDstIp, 0) || 
		!portToString(tLogRow.src_port, strSrcPort) ||
		!portToString(tLogRow.dst_port, strDstPort))
	{
		return FAILED_PARSE_LOG_FIELD_TO_STRING_FROM_FIREWALL_ERROR;
	}

	/* Printing log on user screen */
	printf(LOG_PRINTING_FORMAT, 
		   tLogRow.timestamp,
		   strProtocol,  
		   strAction,
		   tLogRow.hooknum,
		   strSrcIp, 	
		   strDstIp, 	
		   strSrcPort, 
		   strDstPort, 
		   tLogRow.reason,
		   tLogRow.count);
	
	/* Return Suceess */
	return SUCCESS;
}

EReturnValue printDevLogs(char* strLogsDevFormat, const unsigned int uLogSize)
{
	/* Variable Section */
	char* strSingleLogDevFormat;
	EReturnValue rvReturnValue;

	/* Code Section */
	while ((NULL != 
		    (strSingleLogDevFormat = 
		   		strsep(&strLogsDevFormat, 
				   	   LOG_DEV_ITEM_SEPERATOR))))
	{		
		rvReturnValue = printSingleDevLog(strSingleLogDevFormat);
		
		if (SUCCESS != rvReturnValue)
		{
			return rvReturnValue;
		}
	}

	return SUCCESS;
}

EReturnValue showConnectionTable()
{
	/* Variable Definition */	
	char* strConnectionTableDevFormat = NULL;
	unsigned int uConnectionTableSize;

	/* Code Section */	
	/* Reading connection table from firewall */
	EReturnValue rvReturnValue = readConnectionTablesFromFirewall(&strConnectionTableDevFormat, &uConnectionTableSize);

	/* If faild to read connection table */
	if (SUCCESS != rvReturnValue)
	{
		/* Freeing connection table from dev string */
		free(strConnectionTableDevFormat);

		/* Return failure */
		return rvReturnValue;
	}
	
	/* Parsing connection table table */
	rvReturnValue = printDevConnectionTable(strConnectionTableDevFormat, uConnectionTableSize);

	/* Freeing connection table from dev string */
	free(strConnectionTableDevFormat);
	
	/* Return */
	return rvReturnValue;
}

EReturnValue showLog()
{
	/* Variable Definition */	
	char* strLogDevFormat = NULL;
	unsigned int uLogSize;

	/* Code Section */	
	/* Reading logs from firewall */
	EReturnValue rvReturnValue = readLogsFromFirewall(&strLogDevFormat, &uLogSize);

	/* If faild to read logs */
	if (SUCCESS != rvReturnValue)
	{
		/* Freeing logs from dev string */
		free(strLogDevFormat);

		/* Return failure */
		return rvReturnValue;
	}
	
	/* Parsing logs table */
	rvReturnValue = printDevLogs(strLogDevFormat, uLogSize);

	/* Freeing logs from dev string */
	free(strLogDevFormat);
	
	/* Return */
	return rvReturnValue;
}

EReturnValue clearLog()
{
	/* Varaible Section */
	int fdFirewallLogSysfs;
	ssize_t stBytesWritten;
	char arrClearLog[CLEAR_LOG_LENGTH+1];
	
	/* Code Section */
	/* Setting the clear log code */
	arrClearLog[0] = CLEAR_LOG_CODE;

	/* As matter of security, null-terminating the string */
	arrClearLog[CLEAR_LOG_LENGTH] = '\0';

	/* Opening firewall log device sysfs */
	fdFirewallLogSysfs = open(SYSFS_LOG_ATTRIBUTE_LOG_CLEAR_PATH, O_WRONLY);
	
	/* Validate opening firewall log device sysfs */
	if (0 > fdFirewallLogSysfs)
	{
		/* Return error */
		return FAILED_OPEN_SYSFS_LOG_DEVICE_ERROR;
	}
	/* Else, firewall log device sysfs opened successfully */
	else
	{
		/* Writing user code to firewall log device sysfs */
		stBytesWritten = 
			write(fdFirewallLogSysfs, 
				  arrClearLog, 
				  CLEAR_LOG_LENGTH);

		/* Closing firewall log device sysfs */
		close(fdFirewallLogSysfs);
		
		/* Validating written succesfully */
		if (CLEAR_LOG_LENGTH != stBytesWritten)
		{
			/* Return error */
			return FAILED_WRITE_SYSFS_LOG_DEVICE_ERROR;
		}
		
		/* Return success */
		return SUCCESS;
	}

	/* Return error */
	return FAILED_WRITE_SYSFS_LOG_DEVICE_ERROR;
}

/*
 * Based on: https://stackoverflow.com/questions/4553012/checking-if-a-file-is-a-directory-or-just-a-file
 */
BOOL isFile(const char* strFilePath)
{
	struct stat statPathStatus;

	/* Attempting to retrive status from path */
    if (0 != stat(strFilePath, &statPathStatus))
	{
		/* Return failed */
		return FALSE;
	}

	/* Validating regular file */
    return (0 != S_ISREG(statPathStatus.st_mode) ? TRUE : FALSE);
}

BOOL tokenizeLine(char* strLine, const char* strToken, char** arrTokens, const int nLength)
{
	int i = 0;
	char* pToken;

	for (i = 0; nLength > i; i++)
	{
		if (0 == i)
		{
			pToken = strtok(strLine, strToken);
		}
		else
		{
			pToken = strtok(NULL, strToken);
		}

		if (!pToken)
		{
			return FALSE;
		}

		arrTokens[i] = pToken;
	}

	return (NULL == strtok(NULL, strToken)) ? TRUE : FALSE;
}

BOOL addRuleName(rule_t* pRule, char* strName)
{
	int nRuleNameLength = strnlen(strName, RULE_MAX_NAME_LENGTH);

	/* If rule name is invalid */
	if ((RULE_MAX_NAME_LENGTH < nRuleNameLength) || 
		(RULE_MIN_NAME_LENGTH > nRuleNameLength))
	{
		return FALSE;
	}

	/* Copying rule name */
	strcpy(pRule->rule_name, strName);

	return TRUE;
}

BOOL addRuleDirection(rule_t* pRule, char* strDirection)
{
	if (!strcasecmp(strDirection, "in"))
	{
		pRule->direction = DIRECTION_IN;		
	}
	else if (!strcasecmp(strDirection, "out"))
	{
		pRule->direction = DIRECTION_OUT;		
	}
	else if (!strcasecmp(strDirection, "any"))
	{
		pRule->direction = DIRECTION_ANY;		
	}
	else
	{
		return FALSE;
	}

	return TRUE;
}

/*
 * Inspired by: https://stackoverflow.com/questions/10283703/conversion-of-ip-address-to-integer
 */
BOOL stringIPv4ToInteger(char* strIP, unsigned int* pIP, unsigned char* pIPSize)
{
	unsigned int size;
	unsigned int ipbytes[4];

	if (!strcasecmp(strIP, "any"))
	{
		*pIPSize = 0;
		*pIP = 0;

		return TRUE;
	}

	if ( 5 != sscanf(strIP, "%u.%u.%u.%u/%u", &ipbytes[0], &ipbytes[1], &ipbytes[2], &ipbytes[3], &size) )
	{
		return FALSE;
	}

	if ((ipbytes[0] > 255) ||
		(ipbytes[1] > 255) ||
		(ipbytes[2] > 255) ||
		(ipbytes[3] > 255) ||
		(size > 32))
	{
		return FALSE;
	}

	*pIPSize = (unsigned char)size;
	*pIP = ipbytes[3] + ipbytes[2] * 0x100 + ipbytes[1] * 0x10000ul + ipbytes[0] * 0x1000000ul;

	return TRUE;
}

/*
 * Inspired by: http://www.skyfree.org/linux/gatekeeper/ip.C
 */
static unsigned int toPrefixMask(int prefixSize)
 {
	int i;
	unsigned int mask = 0;

	for (i = prefixSize; i > 0; i--)
	{
		mask += (unsigned int) (1 << (32 - i));
	}

	return mask;
 }

 BOOL addIPtoRule(char* strIP, 
 				unsigned int* pRuleIP, 
				unsigned int* pPrefixMask, 
				unsigned char* pPrefixSize)
{
	if (!stringIPv4ToInteger(strIP, pRuleIP, pPrefixSize))
	{
		return FALSE;
	}

	*pPrefixMask = toPrefixMask(*pPrefixSize);

	return TRUE;
}

BOOL addRuleSourceIP(rule_t* pRule, char* strSourceIP)
{
	return addIPtoRule(strSourceIP, 
					   &pRule->src_ip, 
					   &pRule->src_prefix_mask, 
					   &pRule->src_prefix_size);
}

BOOL addRuleDestinationIP(rule_t* pRule, char* strDestinationIP)
{
	return addIPtoRule(strDestinationIP, 
					   &pRule->dst_ip, 
					   &pRule->dst_prefix_mask, 
					   &pRule->dst_prefix_size);
}

BOOL addRuleProtocol(rule_t* pRule, char* strProtocol)
{
	unsigned int uProtocol;
	BOOL bParsedToInt = (1 == sscanf(strProtocol,"%u", &uProtocol)) ? TRUE : FALSE;

	if (bParsedToInt)
	{
		if (255 < uProtocol)
		{
			return FALSE;
		}

		if ((PROT_ICMP 	== uProtocol) || 
			(PROT_TCP	== uProtocol) || 
			(PROT_UDP	== uProtocol) || 
			(PROT_OTHER == uProtocol) || 
			(PROT_ANY	== uProtocol))
		{
			uProtocol = (unsigned char)uProtocol;
		}
		else
		{
			pRule->protocol = PROT_OTHER;
		}
	}
	else
	{
		if (!strcasecmp(strProtocol, "icmp"))
		{
			pRule->protocol = PROT_ICMP;
		}
		else if (!strcasecmp(strProtocol, "tcp"))
		{
			pRule->protocol = PROT_TCP;
		}
		else if (!strcasecmp(strProtocol, "udp"))
		{
			pRule->protocol = PROT_UDP;
		}
		else if (!strcasecmp(strProtocol, "other"))
		{
			pRule->protocol = PROT_OTHER;
		}	
		else if (!strcasecmp(strProtocol, "any"))
		{
			pRule->protocol = PROT_ANY;
		}	
		else
		{
			return FALSE;
		}
	}

	return TRUE;
}

BOOL addPortToRule(unsigned short* pPort, char* strPort)
{
	unsigned int uPort;

	if (!strcasecmp(strPort, "any"))
	{
		*pPort = PORT_ANY;
	}
	else if (!strcasecmp(strPort, ">1023"))
	{
		*pPort = PORT_ABOVE_1023;
	}
	else if (1 != sscanf(strPort, "%u", &uPort))
	{
		return FALSE;
	}
	else if (65535 < uPort)
	{
		return FALSE;
	}
	else if (1023 < uPort)
	{
		*pPort = PORT_ABOVE_1023;
	}
	else
	{
		*pPort = (unsigned short)uPort;
	}

	return TRUE;
}

BOOL addRuleSourcePort(rule_t* pRule, char* strSourcePort)
{
	return addPortToRule(&pRule->src_port, strSourcePort);
}

BOOL addRuleDestinationPort(rule_t* pRule, char* strDestinationPort)
{
	return addPortToRule(&pRule->dst_port, strDestinationPort);
}

BOOL addRuleAck(rule_t* pRule, char* strAck)
{
	if (!strcasecmp(strAck, "yes"))
	{
		pRule->ack = ACK_YES;
	}
	else if (!strcasecmp(strAck, "no"))
	{
		pRule->ack = ACK_NO;
	}
	else if (!strcasecmp(strAck, "any"))
	{
		pRule->ack = ACK_ANY;
	}
	else 
	{
		return FALSE;
	}

	return TRUE;
}

BOOL addRuleAction(rule_t* pRule, char* strAction)
{
	if (!strcasecmp(strAction, "accept"))
	{
		pRule->action = NF_ACCEPT;
	}
	else if (!strcasecmp(strAction, "drop"))
	{
		pRule->action = NF_DROP;
	}
	else 
	{
		return FALSE;
	}

	return TRUE;
}

rule_t* parseToRule(const char* strLine)
{
	char* arrTokens[TOKENS_IN_RULE];
	char* strLineToTokenize = NULL;

	strLineToTokenize = strdup(strLine);

	if (!tokenizeLine(strLineToTokenize, RULE_DELIMETER, arrTokens, TOKENS_IN_RULE))
	{
		free(strLineToTokenize);
		return NULL;
	}

	rule_t* pRule = (rule_t*)malloc(sizeof(rule_t));

	/* Adding rule name */
	if ((!addRuleName(pRule, arrTokens[rule_indexes_rule_name])) || 
		(!addRuleDirection(pRule, arrTokens[rule_indexes_direction])) ||
		(!addRuleSourceIP(pRule, arrTokens[rule_indexes_Source_IP])) ||
		(!addRuleDestinationIP(pRule, arrTokens[rule_indexes_Dest_IP])) ||
		(!addRuleProtocol(pRule, arrTokens[rule_indexes_protocol])) ||
		(!addRuleSourcePort(pRule, arrTokens[rule_indexes_Source_port])) ||
		(!addRuleDestinationPort(pRule, arrTokens[rule_indexes_Dest_port])) ||
		(!addRuleAck(pRule, arrTokens[rule_indexes_ack])) ||
		(!addRuleAction(pRule, arrTokens[rule_indexes_action])))
	{
		free(pRule);		
		pRule = NULL;
	}

	free(strLineToTokenize);

	return pRule;
}

BOOL isEndOfLine(char c)
{
	return ((('\r' == c) || ('\n' == c)) ? TRUE : FALSE);
}

/*
 * According to: https://en.wikipedia.org/wiki/Newline
 */
void lineToString(char* strLine)
{	
	ssize_t sLength = strlen(strLine);

	switch (sLength)
	{
		/* Empty, nothing to change */
		case 0:
		{
			break;
		}
		
		/* Length is 1, checking that char */
		case 1:
		{
			if (isEndOfLine(strLine[0]))
			{
				strLine[0] = '\0';
			}
			
			break;
		}
		
		/* Default case checking for last two chars */
		default:
		{
			if (isEndOfLine(strLine[sLength-1])){
				strLine[sLength-1] = '\0';
			}

			if (isEndOfLine(strLine[sLength-2])){
				strLine[sLength-2] = '\0';
			}			
			
			break;
		}
	}
}

BOOL isRuleExists(rule_t* arrRules[], const unsigned int uLength, char* rule_name)
{
	int i;
	
	for(i = 0; uLength > i; ++i)
	{
		if (!strcmp(arrRules[i]->rule_name, rule_name))
		{
			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Inspired by: https://stackoverflow.com/questions/3501338/c-read-file-line-by-line
 */
EReturnValue readRules(const char* strFilePath, rule_t* arrRules[], const unsigned int uMaxRules, unsigned int* pRulesNumber)
{
	/* Variable Definition */
	FILE* fpRulesFilePointer;
    char* strLine = NULL;		
    size_t sLength = 0;
    ssize_t sReadSize;
	ssize_t sStringSize;
	rule_t* pRule;	
	unsigned int uRuleIndex = 0;
	
	/* Code Section */
	memset(arrRules, 0, uMaxRules*sizeof(rule_t*));

	/* Validating user provided a file */
	if (!isFile(strFilePath))
	{
		/* Return failure */
		return RULE_PATH_IS_NOT_FILE_ERROR;
	}

	/* Opening rules file for reading */
    fpRulesFilePointer = fopen(strFilePath, "r");

	/* If not opened */
    if (!fpRulesFilePointer)
	{
		/* Return failure */
		return FAILED_OPEN_RULES_FILE_ERROR;
	}
    
	/* Initializing rule index */
	uRuleIndex = 0;

	/* Reading next line if not end of file */
    while (EOF != (sReadSize = getline(&strLine, &sLength, fpRulesFilePointer))) 
	{
		/* Replacing end of line in '\0' */
		lineToString(strLine);

		/* Read should contain the '\n', which isn't in rule format */
		sStringSize = strlen(strLine);

		/* If rule line lenght is invalid */
		if ((RULE_MIN_LENGTH > sStringSize) || 
			(RULE_MAX_LENGTH < sStringSize))
		{
			/* Skipping this invalid rule */
			continue;
		}

		/* Parsing to rule */
		pRule = parseToRule(strLine);

		/* If failed to parse rule */
		if (!pRule)
		{
			continue;
		}

		/* If rule with same name exists */
		if (isRuleExists(arrRules, uRuleIndex, pRule->rule_name))
		{
			continue;
		}

		/* Adding current rule */
		arrRules[uRuleIndex++] = pRule;

		/* Rules max number has been reached */
		if (uMaxRules < uRuleIndex)
		{
			break;
		}
    }

	/* Closing file and free line */
	/* Closing file */
    fclose(fpRulesFilePointer);

	/* If read buffer hasn't been freed */
    if (strLine)
	{
		/* Free read buffer */
        free(strLine);

		/* Assign NULL as a matter of security */
		strLine = NULL;
	}

	/* Setting rules number as the updated index */
	*pRulesNumber = uRuleIndex;

	/* Return Success */
	return SUCCESS;
}

void freeRules(rule_t* arrRules[], unsigned int* pRulesNumber)
{
	int i;
	
	for(i = 0; i < *pRulesNumber; ++i)
	{
		free(arrRules[i]);
		arrRules[i] = NULL;
	}

	*pRulesNumber = 0;	
}


char* convertRulesToDevFormat(rule_t* arrRules[], const unsigned int uRulesNumber)
{
	int i = 0;
	char* pRulesDevFormat;
	rule_t* pRule;
	ssize_t sLastSize;
	ssize_t sTotalSize = 0;

	pRulesDevFormat = (char*)calloc(RULE_DEV_MAX_LEN * uRulesNumber + 1, sizeof(char));
	
	if (!pRulesDevFormat)
	{
		return NULL;
	}

	for(i = 0; uRulesNumber > i; ++i)
	{
		pRule = arrRules[i];

		sLastSize = sprintf(pRulesDevFormat + sTotalSize,
							RULE_DEV_FORMAT, 
							pRule->rule_name, 
							pRule->direction, 
							pRule->src_ip, 
							pRule->src_prefix_mask, 
							pRule->src_prefix_size, 
							pRule->dst_ip, 
							pRule->dst_prefix_mask, 
							pRule->dst_prefix_size, 
							pRule->src_port, 
							pRule->dst_port, 
							pRule->protocol, 
							pRule->ack,
							pRule->action);

		sTotalSize += sLastSize;
	}	

	return pRulesDevFormat;
}

EReturnValue loadRules(const char* strFilePath)
{
	/* Variable Definition */
	EReturnValue rvReturnValue;
	unsigned int uRulesNumber;
	rule_t* arrRules[RULES_MAX_NUMBER];
	char* strRulesDevFormat;
	
	/* Code Section */
	/* Reading rules from rules file */
	if (SUCCESS != (rvReturnValue = readRules(strFilePath, arrRules, MAX_RULES, &uRulesNumber)))
	{
		return rvReturnValue;
	}

	/* Converting rules table to rules dev format */
	strRulesDevFormat = convertRulesToDevFormat(arrRules, uRulesNumber);

	/* Free rules array */
	freeRules(arrRules, &uRulesNumber);

	/* If failed to convert to rules dev format */
	if (!strRulesDevFormat)
	{
		return RULE_CONVERTION_TO_DEV_FRMT_FAILED_ERROR;
	}

	/* Writing rules to firewall */
	rvReturnValue = writeRulesToFirewall(strRulesDevFormat);

	/* Free rules dev format string */
	free(strRulesDevFormat);

	/* Return */ 
	return rvReturnValue;
}

BOOL isAction(char* strUserAction, const char* strPossibleAction)
{
	/* Return whether user action matches possible action */
	return (!strncmp(strUserAction, strPossibleAction, USER_ACTION_MAX_LENGTH) ? TRUE : FALSE);
}

/**
 * Description: Translate return value to message and print it
 *
 * Parameters:
 *		eReturnValue	-	Return value
 *
 * Return value: None. Prints returned value as string
 *
 */
void printReturnValue(EReturnValue eReturnValue)
{
	#ifdef PRINT_DEBUG_MESSAGES	
		printf("%s\n", RETURN_VALUE_STRING[eReturnValue]);
	#endif
}

/**
 * Description: Main function to communicate with firewall
 *
 * Parameters:
 *		activate					-	Activating firewall
 *		deactivate					-	Deactivating firewall
 *		show_rules					-	Showing list of rules
 *		clear_rules					-	Clearing list of rules
 *		load_rules					-	Loading list of rules
 *		show_log					-	Deactivating firewall
 *		clear_log					-	Clear log
 *
 * Return value: None
 *
 */
int main(int argc, const char* argv[])
{
	/* Variable Section */
	char* strUserAction;
	EReturnValue eReturnValue = SUCCESS;
	
	/* Code Section */	
	#if DEBUG
		setvbuf(stdout,NULL,_IONBF,0);
		setvbuf(stderr,NULL,_IONBF,0);
		setvbuf(stdin,NULL,_IONBF,0);
	#endif

	#if DEBUG 
	/*
	argc = 2;
	argv[1]="load_rules";
	argv[2]="rules_0.txt";
	*/
	#endif

	/* If, not one argument given */
	if ((2 != argc) && (3 != argc))
	{
		/* Set error return value */
		eReturnValue = USER_ACTION_IS_INVALID_ERROR;
	}
	/* Else, valid number of arguments was given */
	else
	{
		/* Setting user action */
		strUserAction = (char*)argv[USER_ACTION_ARG_INDEX];

		/* If one argument given */
		if (2 == argc)
		{
			/* If activate action */
			if (isAction(strUserAction, ACTIVATE_ACTION))
			{
				eReturnValue = setRulesActiveStatus(TRUE);			
			}
			/* Else, if deactivate action */
			else if (isAction(strUserAction, DEACTIVATE_ACTION))
			{
				eReturnValue = setRulesActiveStatus(FALSE);		
			}
			/* Else, if show rules action */
			else if (isAction(strUserAction, SHOW_RULES_ACTION))
			{
				eReturnValue = showRules();	
			}
			/* Else, if clear rules action */
			else if (isAction(strUserAction, CLEAR_RULES_ACTION))
			{				
				eReturnValue = clearRules();			
			}
			/* Else, if show log action */
			else if (isAction(strUserAction, SHOW_LOG_ACTION))
			{
				eReturnValue = showLog();			
			}
			/* Else, if clear log action */
			else if (isAction(strUserAction, CLEAR_LOG_ACTION))
			{				
				eReturnValue = clearLog();			
			}
			/* Else, if show connection table action */
			else if (isAction(strUserAction, SHOW_CONNECTION_TABLE))
			{				
				eReturnValue = showConnectionTable();			
			}
			/* Else, unrecognized user action */
			else 
			{
				/* Set error return value */
				eReturnValue = USER_ACTION_IS_INVALID_ERROR;
			}
		}
		/* Else, two arguments given */
		else
		{
			/* If load rules action */
			if (isAction(strUserAction, LOAD_RULES_ACTION))
			{	
				eReturnValue = loadRules(argv[RULES_FILE_ARG_INDEX]);
			}
			/* Else, unrecognized user action */
			else 
			{
				/* Set error return value */
				eReturnValue = USER_ACTION_IS_INVALID_ERROR;
			}
		}
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printReturnValue(eReturnValue);
	#endif

	/* Return value */
	return -eReturnValue;
}
