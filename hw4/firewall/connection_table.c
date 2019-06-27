#include "tcp_connection.h"
#include "connection_table.h"

/*
 * Inspired by Reuven Plevinsky;
 * Handling the sysfs code
 * @source: http://course.cs.tau.ac.il/secws16/lectures/
 * 
 */

/* Connection Table Dev Section */
static BOOL 			s_bConnectionTableDeviceOpen    			= FALSE;
static int              s_nConnectionTableDeviceMajorNumber;
static struct device*   pdConnectionTableDevice               	    = NULL;

static size_t 			s_sTotalBytesWrittenToBuffer 				= 0;
static char*			s_pConnectionFromUserWriteBuffer			= NULL;

/* Prototype Functions for Connection Table character driver */
static int     connection_table_open(struct inode *, struct file *);
static ssize_t connection_table_read(struct file *, char *, size_t, loff_t *);
static ssize_t connection_table_write(struct file *, const char *, size_t, loff_t *);
static int     connection_table_release(struct inode *, struct file *);

static struct file_operations fopsConnectionTable = {
	.owner 		= THIS_MODULE,
	.open 		= connection_table_open,
	.read 		= connection_table_read,
	.write		= connection_table_write,
	.release 	= connection_table_release,
};

/* Static Definition */
static LIST_HEAD(s_connection_table_head);  
static unsigned int s_uConnectionsCounter  = 0;   

/* Attributes Section */
/* Connection Table size Attribute Section */
/**
 * Description: Returns connection table size
 *
 * Parameters:
 *		dev			-	The device
 *		attr		-	Device attributes
 *		buf			-	Pointer to buffer
 *
 * Return value: 
 *		ssize_t		-	The size of the connection table
 *
 */
ssize_t get_conn_tab_size(struct device *dev, struct device_attribute *attr, char *buf)
{
	/* Variable Section */
    ssize_t sstTotalCharsWritten = 0;

	/* Code Section */
    /* Writing is active */
    sstTotalCharsWritten = 
		scnprintf(buf, 
				  PAGE_SIZE, 
				  UINT_FORMAT, 
				  s_uConnectionsCounter);

    /* If error occured */
    if (0 >= sstTotalCharsWritten)
    {
		#ifdef PRINT_DEBUG_MESSAGES
        	printk(KERN_ERR FW_DEVICE_NAME_CONNECTION_TABLE WRITTING_SYSFS_FAILED_MSG);
		#endif
    }

	return sstTotalCharsWritten;
}

static DEVICE_ATTR(conn_tab_size, DEV_PERM_BITS_READ, get_conn_tab_size, NULL);

/* Device Read-Write Section */
/*
 * Free all memory of conection table
 * Inspired by: https://isis.poly.edu/kulesh/stuff/src/klist/
 */
void freeConnectionTable(void)
{
	/* Struct Definition */
	connection_row_t* 	pCurrentConnectionRowEntry;
	struct list_head* 	pos;
	struct list_head* 	temp;

	/* Code Section */
	/* Going over the connection table, 
	   freeing rows and pointers, 
	   in a safe manner as we modify it */
	list_for_each_safe(pos, temp, &s_connection_table_head){
		/* Fetching current connection row entry */
		pCurrentConnectionRowEntry = 
			list_entry(pos, connection_row_t, connection_rows_list);

		/* Deleting the list node pointer */
		list_del(pos);

		/* Freeing connection row entry */
		kfree(pCurrentConnectionRowEntry);
	}

	/* Resetting connections counter */
	s_uConnectionsCounter = 0;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_DATA_CLEARED);
	#endif
}

/*
 * Called when connection table device is opened
 * 
 * Inspired by: https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 */
static int connection_table_open(struct inode *inode, struct file *filp)
{
	/* Variable Definition */
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		static int sCounter = 0;
	#endif

	/* Code Section */
	/* If already open - return busy */
	if (s_bConnectionTableDeviceOpen) 
	{
		return -EBUSY;
	}

	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO DEVICE_NAME_CONN_TAB DEVICE_OPENED_D_TIMES_FRMT, sCounter++);
	#endif
	
	/* Flagging device as opened */
	s_bConnectionTableDeviceOpen = TRUE;

	return DEV_SUCCESS;
}

/*
 * Called when a process, which already opened the connection table dev file, attempts to read from it.
 * Each call sends another connection row to user space
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static ssize_t connection_table_read(struct file *fp, char *buff, size_t length, loff_t *ppos)
{
	/* Static Definition */
	static unsigned int 		sConectionRowsDelivered = 0;
	static struct list_head*	pLastDeliveredConnectionRow;

	/* Vairiable Section */
	connection_row_t* 	pConnectionRow;
	int  				nBytesToCopy = 0;
	char 				strConnectionRow[CONNECTION_TABLE_DEV_MAX_LEN + 1];

	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_READ_BEGIN);
	#endif

	/* If first row to deliver */
	if (0 == sConectionRowsDelivered)
	{
		/* Setting last delivered as the head */
		pLastDeliveredConnectionRow = &s_connection_table_head;
	}

	/* If all connection rows delivered - return 0 signifying end of file */
	if (sConectionRowsDelivered == s_uConnectionsCounter) 
	{
		#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
			printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_READ_FINISHED);
		#endif

		/* Resetting the counter */
		sConectionRowsDelivered = 0;

		/* Return success */
		return DEV_SUCCESS;
	}

	/* Fetching current connection row */
	pConnectionRow = list_entry(pLastDeliveredConnectionRow->next, connection_row_t, connection_rows_list);

	/* Parsing connection row fields to firewall dev format  */
	if (CONNECTION_TABLE_DEV_MIN_LEN > 
		sprintf(strConnectionRow, 
			    CONNECTION_TABLE_DEV_FORMAT, 
			    pConnectionRow->initiator_ip,	  	
                pConnectionRow->initiator_port,
                pConnectionRow->responder_ip,
                pConnectionRow->responder_port,
                pConnectionRow->protocol,
                pConnectionRow->initiator_state,
                pConnectionRow->responder_state,
                pConnectionRow->time_added))
	{
		/* Failed to parse - return error */
		return -EINVAL;
	}

	/* We shall copy the the formatted string */
	nBytesToCopy = strlen(strConnectionRow);
 	
	/* Validating buffer length is sufficient */
	if (length < nBytesToCopy)
	{
		/* Not enought place - return error */
		return -EINVAL;
	}

	/* Writting to user buffer */
	if (DEV_SUCCESS != 
		copy_to_user(buff, 
					 strConnectionRow, 
					 nBytesToCopy))
	{
		/* Failed to copy to user buffer */
		return -EIO;
	}

	/* Updating counter */
	++sConectionRowsDelivered;

	/* Updating last deliverd connection row */
	pLastDeliveredConnectionRow = pLastDeliveredConnectionRow->next;

	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_READ_ENDED);
	#endif

	/* Return number of bytes assigned into the buffer */
	return nBytesToCopy;	
}

/**
 * Description: Frees the buffer allocated for writing connection table to user
 *
 * Parameters: None
 *
 * Return value: None
 *
 */
void freeConnectionFromUserWriteBuffer(void)
{
	/* Code Section */
	/* Resetting counter */	
	s_sTotalBytesWrittenToBuffer = 0;

	/* If buffer exists */
	if (s_pConnectionFromUserWriteBuffer)
	{
		/* Free buffer */
		kfree(s_pConnectionFromUserWriteBuffer);

		/* Put NULL to indicate it's freed, and to prevent data leak */
		s_pConnectionFromUserWriteBuffer = NULL;
	}
}

/*
 * Called when a process writes to connection table dev file
 * Each call writes connection from user space
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static ssize_t connection_table_write(struct file *fp, const char *buff, size_t length, loff_t *ppos)
{
	/* Variable Definition */
	long lFreeSpaceToCopy = 0;
	long lBytesToCopy = 0;

	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_WRITE_BEGIN);
	#endif

	/* Invalid length given */
	if (0 >= length)
	{
		/* Return failure */
		return -EINVAL;
	}

	/* First call in write session - buffer uninitialized */
	if (!s_pConnectionFromUserWriteBuffer)
	{		
		/* Allocate buffer to copy data from user space */
		s_pConnectionFromUserWriteBuffer = (char*)kcalloc(NEW_CONNECTION_DEV_MAX_LEN+1, sizeof(char), GFP_ATOMIC);

		/* If wasn't allocated - not enough memory */
		if (!s_pConnectionFromUserWriteBuffer)
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR MEMORY_ALLOCATION_FAILED_MSG);
			#endif

			return -ENOMEM;
		}

		/* Resetting counter */
		s_sTotalBytesWrittenToBuffer = 0;
	}

	/* Calculating free space in buffer */
	lFreeSpaceToCopy = 
		(NEW_CONNECTION_DEV_MAX_LEN - 1 - s_sTotalBytesWrittenToBuffer);

	/* No more free space - reached invalid state */
	if (0 > lFreeSpaceToCopy)
	{
		/* Free connection write buffer */
		freeConnectionFromUserWriteBuffer();

		/* Return failure */
		return -EDQUOT;
	}

	/* Ensuring bytes to copy dosn't exceed free space */
	lBytesToCopy = 
		(length > lFreeSpaceToCopy) ?
			lFreeSpaceToCopy : length;

	/* Copying from user to write buffer */
	if (DEV_SUCCESS != 
		copy_from_user(
			s_pConnectionFromUserWriteBuffer + s_sTotalBytesWrittenToBuffer,
			buff,
			lBytesToCopy))
	{
		/* Free connection write buffer */
		freeConnectionFromUserWriteBuffer();

		/* Return failure */
		return -EIO;
	}

	/* Updating toatl bytes counter */
	s_sTotalBytesWrittenToBuffer += lBytesToCopy;

	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_WRITE_ENDED);
	#endif

	/* Return number of bytes copyied */
	return lBytesToCopy;
}

/**
 * Description: Validating connection protocol
 *
 * Parameters:
 *		protocol	-	The protocol of the packet
 *
 * Return value: 
 *		BOOL		-	Boolean indicator whether valid protool for connection
 *
 */
BOOL validateConnectionProtocol(unsigned char protocol)
{
	/* Code Section */
	/* Handling according to protocol number */
	switch (protocol)
	{
		/* In case it's TCP protocol */
		case PROTOCOL_CONNECTION_TCP:		
		{
			/* Return true */
			return TRUE;
		}
		/* Default case, it's not */
		default:
		{
			/* Return false */
			return FALSE;
		}
	}

	/* Return false */
	return FALSE;
}

/**
 * Description: Validating new connection protocol
 *
 * Parameters:
 *		pConnectionRaw	-	Pointer to conection row in it's raw form
 *
 * Return value: 
 *		BOOL			-	Boolean indicator whether valid connection
 *
 */
BOOL validateNewConnection(new_connection_raw_t* pConnectionRaw)
{
	/* Code Section */
	/* Validating new connection protocol */
	return (!validateConnectionProtocol(pConnectionRaw->protocol)) ? FALSE : TRUE;
}

/**
 * Description: Parsing connection from write buffer
 *
 * Parameters: None
 *
 * Return value: 
 *		BOOL			-	Boolean indicator whether parsed successfully
 *
 */
BOOL parseConnectionFromWriteBuffer(void)
{
	/* Variable Definition */
	BOOL					bIsAdded;
	size_t 					sLength;
	new_connection_raw_t 	cConnectionRaw;

	/* Code Section */
	/* If nothing to handle */
	if (NULL == s_pConnectionFromUserWriteBuffer)
	{
		return FALSE;
	}

	/* Null ternimating to string as matter of security */
	s_pConnectionFromUserWriteBuffer[s_sTotalBytesWrittenToBuffer] = '\0';	
	sLength = strnlen(s_pConnectionFromUserWriteBuffer, NEW_CONNECTION_DEV_MAX_LEN + 1);

	/* If connection dev format lenght is zero */
	if (0 == sLength)
	{
		return FALSE;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_PARSING_FRMT, s_pConnectionFromUserWriteBuffer);
	#endif

	/* If rule dev format lenght exceeds maximal length */
	if (NEW_CONNECTION_DEV_MAX_LEN < sLength)
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR DEVICE_DATA_LENGTH_INVALID_ERROR);
		#endif

		return FALSE;
	}
	
	/* Parsing to raw rule format */
	if (FIELDS_IN_NEW_CONNECTION_DEV != 
		sscanf(s_pConnectionFromUserWriteBuffer,
			   NEW_CONNECTION_DEV_FORMAT,
			   &cConnectionRaw.initiator_ip,	
			   &cConnectionRaw.initiator_port,
			   &cConnectionRaw.responder_ip,
			   &cConnectionRaw.responder_port,
			   &cConnectionRaw.protocol))
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR DEVICE_FAILED_PARSE_DATA_ERROR);
		#endif

		return FALSE;
	}

	/* Validating connection */	
	if (!validateNewConnection(&cConnectionRaw))
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR DEVICE_DATA_IS_INVALID_ERROR);
		#endif
		
		return FALSE;
	}

	/* Adding validated connection */
	bIsAdded = addNewTCPToConnectionTable(&cConnectionRaw);

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_PARSED_SUCCESSFULLY);
	#endif

	/* Return whether added succesfully */
	return bIsAdded;
}

/*
 * Called when connection table dev is released, when there is no process using it.
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static int connection_table_release(struct inode *inode, struct file *file)
{
	/* Variable Definition */
	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		static int sCounter = 0;
	#endif

	/* Code Section */	
	/* Flagging as closed */
	s_bConnectionTableDeviceOpen = FALSE;

	/* If closing after write - handle data */
	if (s_sTotalBytesWrittenToBuffer)
	{
		/* If no data to handle */
		if (!s_pConnectionFromUserWriteBuffer)
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_WRITE_FINISHED_NO_DATA_ERROR);
			#endif
		}
		/* Else, handling data */
		else
		{
			#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
				printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_WRITE_FINISHED);
			#endif

			/* Parse connection from write buffer */
			parseConnectionFromWriteBuffer();

			/* Free the write buffer */
			freeConnectionFromUserWriteBuffer();
		}
	}

	#ifdef PRINT_DEBUG_MESSAGES_VERBOSE
		printk(KERN_INFO DEVICE_NAME_CONN_TAB DEVICE_RELEASED_D_TIMES_FRMT, sCounter++);
	#endif

	return DEV_SUCCESS;
}

/**
 * Description: Initializing connection table static variables
 *
 * Parameters: None
 *
 * Return value: None
 *
 */
void initializeConnectionTableStaticVariables(void)
{
	/* Code Section */
	s_bConnectionTableDeviceOpen    = FALSE;
	pdConnectionTableDevice         = NULL;

	s_uConnectionsCounter			= 0;
}

/**
 * Description: Initializing connection table device
 *
 * Parameters: 
 * 		pcFirewallClass		-	Firewall device class
 *
 * Return value: 
 * 		EDevReturnValue		- Status of device initialization
 *
 */
EDevReturnValue connection_table_device_init(struct class* pcFirewallClass)
{
	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_INIT_BEGIN);
	#endif

	/* Initialize connection table variables */
	initializeConnectionTableStaticVariables();

	/* Register connection char device */
	s_nConnectionTableDeviceMajorNumber = register_chrdev(0, DEVICE_NAME_CONN_TAB, &fopsConnectionTable);
	
	/* Checking major number correctness */
	if (0 > s_nConnectionTableDeviceMajorNumber)
	{
		/* Return error */
		return SYSFS_CHAR_DEVICE_REGISTRING_FAILED;
	}

	/* Create sysfs device */
	pdConnectionTableDevice = 
		device_create(
			pcFirewallClass, 
			NULL, 
			MKDEV(s_nConnectionTableDeviceMajorNumber, MINOR_CONN_TAB), 
			NULL, 
			FW_DEVICE_NAME_CONNECTION_TABLE); 
	
	/* Checking error in sysfs connection table device */
	if (IS_ERR(pdConnectionTableDevice))
	{				
		/* Unregistering char device */		
		unregister_chrdev(s_nConnectionTableDeviceMajorNumber, DEVICE_NAME_CONN_TAB);

		/* Return error */
		return SYSFS_CHAR_DEVICE_CREATION_FAILED;
	}
	
	/* Create sysfs file attributes	*/
	if (device_create_file(
			pdConnectionTableDevice, 
			(const struct device_attribute *)&dev_attr_conn_tab_size.attr))
	{
		/* Destroying device */
		device_destroy(pcFirewallClass, MKDEV(s_nConnectionTableDeviceMajorNumber, MINOR_CONN_TAB));
		
		/* Unregistering char device */		
		unregister_chrdev(s_nConnectionTableDeviceMajorNumber, DEVICE_NAME_CONN_TAB);

		/* Return error */
		return SYSFS_FILE_CREATION_FAILED;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_CONNECTION_TABLE DEVICE_INIT_ENDED);
	#endif

	/* Return success */
	return DEV_SUCCESS;
}

/**
 * Description: Destroying of connection table device
 *
 * Parameters: 
 * 		pcFirewallClass		-	Firewall device class
 *
 * Return value: 
 * 		EDevReturnValue		- Status of device destruction
 *
 */
void connection_table_device_destroy(struct class* pcFirewallClass)
{
	/* Code Section */
	/* Free connection write buffer */
	freeConnectionFromUserWriteBuffer();

    /* Free connection table */
    freeConnectionTable();

	/* Removing sysfs file */
	device_remove_file(pdConnectionTableDevice, (const struct device_attribute *)&dev_attr_conn_tab_size.attr);

	/* Destroying device */
	device_destroy(pcFirewallClass, MKDEV(s_nConnectionTableDeviceMajorNumber, MINOR_CONN_TAB));
	
	/* Unregistering char device */		
	unregister_chrdev(s_nConnectionTableDeviceMajorNumber, DEVICE_NAME_CONN_TAB);

	/* Initialize connection table variables */
	initializeConnectionTableStaticVariables();
}

/**
 * Description: Removing irrelavent rows from connection table
 *
 * Parameters: None
 *
 * Return value: None
 *
 */
void removeIrrelaventRows(void)
{
    /* Struct Definition */
	connection_row_t* 	pCurrentConnectionRowEntry;

	struct list_head* 	pos;
	struct list_head* 	temp;

    /* Code Section */
    /* Removing all irrelevant rows for all protocols */
    list_for_each_safe(pos, temp, &s_connection_table_head){
		/* Fetching current connection entry */
		pCurrentConnectionRowEntry = 
			list_entry(pos, connection_row_t, connection_rows_list);

        /* If row is irrelevant according to TCP protocol */
        if (isIrrelaventTCPRow(pCurrentConnectionRowEntry))
        {
            #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO CONECTION_ROW_REMOVED_FRMT, 
                        CONNECTION_ROLE_STRING[CONNECTION_INITIATOR], 
                        pCurrentConnectionRowEntry->initiator_ip, 
                        pCurrentConnectionRowEntry->initiator_port, 
                        TCP_STATE_STRING[pCurrentConnectionRowEntry->initiator_state], 
                        CONNECTION_ROLE_STRING[CONNECTION_RESPONDER], 
                        pCurrentConnectionRowEntry->responder_ip, 
                        pCurrentConnectionRowEntry->responder_port, 
                        TCP_STATE_STRING[pCurrentConnectionRowEntry->responder_state], 
                        pCurrentConnectionRowEntry->protocol, 
                        pCurrentConnectionRowEntry->time_added);
            #endif

            list_del(pos);
            kfree(pCurrentConnectionRowEntry);

            s_uConnectionsCounter--;

            #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO TOTAL_CONECTION_ROWS_FRMT, s_uConnectionsCounter);
            #endif
        }
	}
}

/**
 * Description: Adding connection to connection talbe
 *
 * Parameters:
 *		pcConnectionRow	-	Pointer to connection row
 *
 * Return value: 
 *		BOOL			-	Boolean indicator if added successfully
 *
 */
BOOL    addToConnectionTable(connection_row_t*              pcConnectionRow)
{
    /* Code Section */
    /* If nothing to add */
    if (!pcConnectionRow)
    {
        /* Return failure */
        return FALSE;
    }

	/* Removing irrelavent packets */	
	removeIrrelaventRows(); 

    /* Add to list */
    list_add(&(pcConnectionRow->connection_rows_list), &s_connection_table_head);

    /* Increment counter */
    ++s_uConnectionsCounter;

    #ifdef PRINT_DEBUG_MESSAGES_VERBOSE
        printk(KERN_INFO TOTAL_CONECTION_ROWS_FRMT, s_uConnectionsCounter);
    #endif

    /* Return success */
    return TRUE;
}

/**
 * Description: Detecting if connection row matches initiator
 *
 * Parameters:
 * 		pPacketInfo				-	Pointer to packet info
 *		pcConnectionRow			-	Pointer to connection row
 *		bCheckBothDirections	-	Indicator wehther to check both directions, 
 *									used for incoming packets, not for outgoing which are from proxy
 *
 * Return value: 
 *		BOOL			-	Boolean indicator if connection row matches initiator
 *
 */
BOOL isInitiator(fw_packet_info*      pPacketInfo,
                 connection_row_t*    pcConnectionRow,
				 BOOL                 bCheckBothDirections)
{
	/* Variable Definition */
	BOOL bIsSrcMatch	=	FALSE;
	BOOL bIsDstMatch	=	FALSE;

    /* Code Section */
    /* If current row non-existant */
    if (!pcConnectionRow)
    {
        return FALSE;
    }

	bIsSrcMatch = ((  pPacketInfo->src_ip     ==  pcConnectionRow->initiator_ip   ) && 
              	   (  pPacketInfo->src_port   ==  pcConnectionRow->initiator_port ));

	bIsDstMatch = ((  pPacketInfo->dst_ip     ==  pcConnectionRow->responder_ip   ) && 
              	   (  pPacketInfo->dst_port   ==  pcConnectionRow->responder_port ));

    /* Checking if match same direction */
    if (pPacketInfo->protocol   !=  pcConnectionRow->protocol)
	{
		return FALSE;
	}

	return bCheckBothDirections ? (bIsSrcMatch && bIsDstMatch) : (bIsSrcMatch || bIsDstMatch);
}

/**
 * Description: Detecting if connection row matches responder
 *
 * Parameters:
 * 		pPacketInfo				-	Pointer to packet info
 *		pcConnectionRow			-	Pointer to connection row
 *		bCheckBothDirections	-	Indicator wehther to check both directions, 
 *									used for incoming packets, not for outgoing which are from proxy
 *
 * Return value: 
 *		BOOL			-	Boolean indicator if connection row matches responder
 *
 */
BOOL isResponder(fw_packet_info*      pPacketInfo,
                 connection_row_t*    pcConnectionRow,
				 BOOL                 bCheckBothDirections)
{
	/* Variable Definition */
	BOOL bIsSrcMatch	=	FALSE;
	BOOL bIsDstMatch	=	FALSE;

    /* Code Section */
    /* If current row non-existant */
    if (!pcConnectionRow)
    {
        return FALSE;
    }

	bIsSrcMatch = ((  pPacketInfo->src_ip     ==  pcConnectionRow->responder_ip   ) && 
              	   (  pPacketInfo->src_port   ==  pcConnectionRow->responder_port ));

	bIsDstMatch = ((  pPacketInfo->dst_ip     ==  pcConnectionRow->initiator_ip   ) && 
              	   (  pPacketInfo->dst_port   ==  pcConnectionRow->initiator_port ));

    /* Checking if match same direction */
    if (pPacketInfo->protocol   !=  pcConnectionRow->protocol)
	{
		return FALSE;
	}

	return bCheckBothDirections ? (bIsSrcMatch && bIsDstMatch) : (bIsSrcMatch || bIsDstMatch);
}

/**
 * Description: Finds the connection row that matches packet info
 *
 * Parameters:
 * 		pPacketInfo			-	Pointer to packet info
 *		pRole				-	Pointer to packet sender role 			[out parameter]
 *		ppcrConnectionRow	-	Pointer to pointer to connection row 	[out parameter]
 *		bIsFromProxy		-	Boolean indicator is packet from proxy
 *
 * Return value: 
 *		BOOL				-	Boolean indicator if connection row found
 *
 */
BOOL findConnectionRow(fw_packet_info*     pPacketInfo, 
                       connection_role_t*  pRole,
                       connection_row_t**  ppcrConnectionRow,
					   BOOL                bIsFromProxy)
{
    /* Struct Definition */
	connection_row_t* 	pCurrentConnectionRowEntry;
	struct list_head* 	pos;
	struct list_head* 	temp;

	/* Code Section */
	/* Going over the connection table */
	list_for_each_safe(pos, temp, &s_connection_table_head){
		/* Fetching current connection entry */
		pCurrentConnectionRowEntry = 
			list_entry(pos, connection_row_t, connection_rows_list);

		/* If sender is the connection initiator */
        if (isInitiator(pPacketInfo, pCurrentConnectionRowEntry, bIsFromProxy))
        {
            /* Setting connection row */
			*ppcrConnectionRow = pCurrentConnectionRowEntry;

            *pRole = CONNECTION_INITIATOR;

            #ifdef PRINT_DEBUG_MESSAGES_VERBOSE
                printk(KERN_INFO PACKET_CONNECTION_ROW_FOUND);
            #endif

            /* Return success */
            return TRUE;
        }
        /* Else, if sender is the connection responder */
        else if (isResponder(pPacketInfo, pCurrentConnectionRowEntry, bIsFromProxy))
        {
            /* Setting connection row */
			*ppcrConnectionRow = pCurrentConnectionRowEntry;

            *pRole = CONNECTION_RESPONDER;

            #ifdef PRINT_DEBUG_MESSAGES_VERBOSE
                printk(KERN_INFO PACKET_CONNECTION_ROW_FOUND);
            #endif

            /* Return success */
            return TRUE;
        }
	}

    /* Return fail */
    return FALSE;
}

/**
 * Description: Finds if there is already a connection for packet
 *
 * Parameters:
 * 		pPacketInfo			-	Pointer to packet info
 *
 * Return value: 
 *		BOOL				-	Boolean indicator if there is already a connection for packet
 *
 */
BOOL isConnectionExists(fw_packet_info*     pPacketInfo)
{
	/* Struct Definition */
	connection_row_t* 	pCurrentConnectionRowEntry;
	struct list_head* 	pos;
	struct list_head* 	temp;

	/* Code Section */
	/* Removing irrelavent packets */	
    removeIrrelaventRows();

	/* Going over the connection table */
	list_for_each_safe(pos, temp, &s_connection_table_head) {
		/* Fetching current connection entry */
		pCurrentConnectionRowEntry = 
			list_entry(pos, connection_row_t, connection_rows_list);

		/* If connection existing row entry has the same protocol type */
		if (pCurrentConnectionRowEntry->protocol			== 	pPacketInfo->protocol)
		{
			/* If packet has existing connection row as initiator */
			if ((pCurrentConnectionRowEntry->initiator_ip 	== 	pPacketInfo->src_ip) 		&&
				(pCurrentConnectionRowEntry->initiator_port ==	pPacketInfo->src_port) 		&&
				(pCurrentConnectionRowEntry->responder_ip 	== 	pPacketInfo->dst_ip)		&&
				(pCurrentConnectionRowEntry->responder_port	== 	pPacketInfo->dst_port))
			{
				#ifdef PRINT_DEBUG_MESSAGES
					printk(KERN_INFO PACKET_CONNECTION_ROW_ALREADY_EXISTS);
				#endif

				return TRUE;
			}

			/* If packet has existing connection row as responder */
			if ((pCurrentConnectionRowEntry->initiator_ip 	== 	pPacketInfo->dst_ip) 		&&
				(pCurrentConnectionRowEntry->initiator_port ==	pPacketInfo->dst_port) 		&&
				(pCurrentConnectionRowEntry->responder_ip 	== 	pPacketInfo->src_ip)		&&
				(pCurrentConnectionRowEntry->responder_port	== 	pPacketInfo->src_port))
				
			{
				#ifdef PRINT_DEBUG_MESSAGES
					printk(KERN_INFO PACKET_CONNECTION_ROW_ALREADY_EXISTS);
				#endif

				return TRUE;
			}
		}
	}

    /* Return fail */
    return FALSE; 
}

/**
 * Description: Returns whether verdict should be set according to connection table
 *
 * Parameters:
 * 		pPacketInfo			-	Pointer to packet info
 *
 * Return value: 
 *		BOOL				-	Boolean indicator if verdict should be set according to connection table
 *
 */
BOOL isConnectionTableVerdict(struct sk_buff*	skb,
						 	  fw_packet_info* 	pPacketInfo)
{
	/* Code Section */
	return isConnectionTableVerdictTCP(skb, pPacketInfo);
}

/**
 * Description: Adds new connection for packet if needed
 *
 * Parameters:
 * 		skb					-	The packet
 * 		pPacketInfo			-	Pointer to packet info
 * 		ppcConnectionRow	-	Pointer to pointer to connection row 	[out parameter]
 *
 * Return value: 
 *		BOOL				-	Boolean indicator if new connection was added
 *
 */
BOOL addPacketToConnectionTableIfNeeded(struct sk_buff*   	skb,
                                        fw_packet_info*   	pPacketInfo,
										connection_row_t**	ppcConnectionRow)
{
    /* Variable Definition */
    BOOL bAdded = FALSE;

    /* Code Section */
    /* If packet is not allowed - no need to add it */
    if (VERDICT_ALLOW != pPacketInfo->action)
    {
        return FALSE;
    }

	/* If connection already exists, no need to add */
	if (isConnectionExists(pPacketInfo))
	{
		return FALSE;
	}

    bAdded = addPacketToConnectionTableIfNeededTCP(skb, pPacketInfo, ppcConnectionRow);

    #ifdef PRINT_DEBUG_MESSAGES
        /* If connection added */
        if (bAdded)
        {
            printk(KERN_INFO CONNECTION_ADDED);
        }
    #endif

    /* Returning whether need to add to connection table */
    return bAdded;
}

/**
 * Description: Returns incoming packet verdict according to connection table
 *
 * Parameters:
 * 		skb					-	The packet
 * 		pPacketInfo			-	Pointer to packet info
 * 		ppcConnectionRow	-	Pointer to pointer to connection row 	[out parameter]
 *
 * Return value: 
 *		BOOL				-	Boolean indicator if verdict set
 *
 */
BOOL setIncomingPacketVerdictByConnectionTable(struct sk_buff*   	skb,
                                       		   fw_packet_info*   	pPacketInfo,
									   		   connection_row_t**	ppcConnectionRow)
{
    /* Varaible Definition */
    connection_role_t   trSenderRole;    

    /* Code Section */
    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO SETTING_PACKET_VERDICT_BY_CONNECTION_TABLE);
    #endif

    /* If connection not found in connection table */
    if (!findConnectionRow(pPacketInfo, &trSenderRole, ppcConnectionRow, TRUE))
    {
        #ifdef PRINT_DEBUG_MESSAGES
            printk(KERN_ERR PACKET_CONNECTION_ROW_NOT_FOUND);
        #endif

        /* Setting action and reason */
        pPacketInfo->reason = REASON_CONNECTION_NOT_FOUND;
        pPacketInfo->action = VERDICT_BLOCK;

		/* Retrun not found */
        return FALSE;
    }

    /* Handling rows state according to protocol machine state */
    switch (pPacketInfo->protocol)
    {
        /* Protocol is TCP */
        case PROT_TCP:
        {
            /* Handling rows state according to TCP protocol machine state */
            pPacketInfo->reason = REASON_CONNECTION_TABLE_VERDICT;
            pPacketInfo->action = handlePacketTCPConnection(skb, pPacketInfo, trSenderRole, *ppcConnectionRow);

            /* End of case */
            return TRUE;
        }

		/* Protocol is unknown - should never get here */
		default:
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR PACKET_CONNECTION_PROTOCOL_IS_ILLEGAL);
			#endif

			/* Default setting action to block */
			pPacketInfo->reason = REASON_CONNECTION_PROTOCOL_ILLEGAL;
			pPacketInfo->action = VERDICT_BLOCK;

			/* Retrun not handled */
			return FALSE;
		}
    } 

	/* Retrun not handled */
	return FALSE;
}

/**
 * Description: Returns outgoing packet verdict according to connection table
 *
 * Parameters:
 * 		skb					-	The packet
 * 		pPacketInfo			-	Pointer to packet info
 * 		ppcConnectionRow	-	Pointer to pointer to connection row 	[out parameter]
 *
 * Return value: 
 *		BOOL				-	Boolean indicator if verdict set
 *
 */
BOOL setOutgoingPacketVerdictByConnectionTable(struct sk_buff*   	skb,
                                       		   fw_packet_info*   	pPacketInfo,
											   connection_role_t*   pSenderRole,
									   		   connection_row_t**	ppcConnectionRow)
{
	/* Code Section */
    #ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO SETTING_PACKET_VERDICT_BY_CONNECTION_TABLE);
    #endif

    /* If connection not found in connection table */
    if (!findConnectionRow(pPacketInfo, pSenderRole, ppcConnectionRow, FALSE))
    {
        #ifdef PRINT_DEBUG_MESSAGES
            printk(KERN_ERR PACKET_CONNECTION_ROW_NOT_FOUND);
        #endif

        /* Setting action and reason */
        pPacketInfo->reason = REASON_CONNECTION_NOT_FOUND;
        pPacketInfo->action = VERDICT_BLOCK;

		/* Retrun not found */
        return FALSE;
    }

    /* Handling rows state according to protocol machine state */
    switch (pPacketInfo->protocol)
    {
        /* Protocol is TCP */
        case PROT_TCP:
        {
            /* Handling rows state according to TCP protocol machine state */
            pPacketInfo->reason = REASON_CONNECTION_TABLE_VERDICT;
            pPacketInfo->action = handlePacketTCPConnection(skb, pPacketInfo, *pSenderRole, *ppcConnectionRow);

			/* Return handeled */
			return TRUE;
        }

		/* Protocol is unknown */
		default:
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR PACKET_CONNECTION_PROTOCOL_IS_ILLEGAL);
			#endif

			/* Default setting action to block */
			pPacketInfo->reason = REASON_CONNECTION_PROTOCOL_ILLEGAL;
			pPacketInfo->action = VERDICT_BLOCK;

			/* Retrun not handled */
			return FALSE;
		}
    } 

	/* Retrun not handled */
	return FALSE;
}

#ifdef PRINT_DEBUG_MESSAGES
/**
 * Description: Prints connection table, for debug proposes
 *
 * Parameters: None
 *
 * Return value: None
 *
 */
void printConnectionTable(void)
{
    /* Struct Definition */
	connection_row_t* 	pCurrentConnectionRowEntry;

	struct list_head* 	pos;
	struct list_head* 	temp;

    /* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
        printk(KERN_INFO CONECTION_TABLE);
	#endif

    /* Going over connection table */
    list_for_each_safe(pos, temp, &s_connection_table_head) {
		/* Fetching current connection entry */
		pCurrentConnectionRowEntry = 
			list_entry(pos, connection_row_t, connection_rows_list);

        #ifdef PRINT_DEBUG_MESSAGES
                printk(KERN_INFO CONECTION_ROW_PRINT_FRMT, 
                        CONNECTION_ROLE_STRING[CONNECTION_INITIATOR], 
                        pCurrentConnectionRowEntry->initiator_ip, 
                        pCurrentConnectionRowEntry->initiator_port, 
                        TCP_STATE_STRING[pCurrentConnectionRowEntry->initiator_state], 
                        CONNECTION_ROLE_STRING[CONNECTION_RESPONDER], 
                        pCurrentConnectionRowEntry->responder_ip, 
                        pCurrentConnectionRowEntry->responder_port, 
                        TCP_STATE_STRING[pCurrentConnectionRowEntry->responder_state], 
                        pCurrentConnectionRowEntry->protocol, 
                        pCurrentConnectionRowEntry->time_added);
        #endif
	}
}
#endif
