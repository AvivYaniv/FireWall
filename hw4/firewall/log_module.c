#include "log_module.h"

/*
 * Inspired by Reuven Plevinsky;
 * Handling the sysfs code
 * @source: http://course.cs.tau.ac.il/secws16/lectures/
 * 
 */

/* Log Dev Section */
static BOOL 			s_bLogDeviceOpen 		 	= FALSE;
static int              s_nLogDeviceMajorNumber;
static struct device*   pdLogDevice               	= NULL;

/* Prototype Functions for Log character driver */
static int     log_open(struct inode *, struct file *);
static ssize_t log_read(struct file *, char *, size_t, loff_t *);
static int     log_release(struct inode *, struct file *);

static struct file_operations fopsLog = {
	.owner 		= THIS_MODULE,
	.open 		= log_open,
	.read 		= log_read,
	.release 	= log_release,
};

/* Log Section */
static LIST_HEAD(s_log_list_head);
static unsigned int		s_uLogLinesCounter						= 0;

/* Methods Section */
/* Attributes Section */
/* Log size Attribute Section */
ssize_t get_log_size(struct device *dev, struct device_attribute *attr, char *buf)
{
	/* Variable Section */
    ssize_t sstTotalCharsWritten = 0;

	/* Code Section */
    /* Writing is active */
    sstTotalCharsWritten = 
		scnprintf(buf, 
				  PAGE_SIZE, 
				  UINT_FORMAT, 
				  s_uLogLinesCounter);

    /* If error occured */
    if (0 >= sstTotalCharsWritten)
    {
		#ifdef PRINT_DEBUG_MESSAGES
        	printk(KERN_ERR FW_DEVICE_NAME_LOG WRITTING_SYSFS_FAILED_MSG);
		#endif
    }

	return sstTotalCharsWritten;
}

static DEVICE_ATTR(log_size, DEV_PERM_BITS_READ, get_log_size, NULL);

/*
 * Inspired by: https://isis.poly.edu/kulesh/stuff/src/klist/
 */
void freeLog(void)
{
	/* Struct Definition */
	log_row_t* 			pCurrentLogRowEntry;
	struct list_head* 	pos;
	struct list_head* 	temp;

	/* Code Section */
	/* Going over the log list, 
	   freeing rows and pointers, 
	   in a safe manner as we modify it */
	list_for_each_safe(pos, temp, &s_log_list_head){
		/* Fetching current log row entry */
		pCurrentLogRowEntry = 
			list_entry(pos, log_row_t, log_rows_list);

		/* Deleting the list node pointer */
		list_del(pos);

		/* Freeing log row entry */
		kfree(pCurrentLogRowEntry);
	}

	/* Resetting log rows counter */
	s_uLogLinesCounter = 0;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_DATA_CLEARED);
	#endif
}

/* Active Attribute Section */
ssize_t set_log_clear(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	/* Code Section */
	/* If buffer is empty */
    if (NULL == buf)
    {
        return -USER_CODE_MORE_IS_NULL_ERROR;    
    }
    /* If more than one argument */
    else if (1 != count)    
    {		
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_RECIVED_TOO_MUCH_DATA_ERROR);
		#endif

        return -USER_CODE_MORE_THAN_ONE_ARG_ERROR;		
    }
    /* Else, checking user code */
    else
    {
        /* Any user code clears te log */
		freeLog();

		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO FW_DEVICE_NAME_LOG " " CLEAR_LOG_ACTION "\n");
		#endif
    }
	
    /* Returning bytes read counter */
	return count;
}

static DEVICE_ATTR(log_clear, DEV_PERM_BITS_WRITE, NULL, set_log_clear);

/* Device Read-Write Section */
/*
 * Called when log device is opened
 * 
 * Inspired by: https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 */
static int log_open(struct inode *inode, struct file *filp)
{
	/* Variable Definition */
	#ifdef PRINT_DEBUG_MESSAGES
		static int sCounter = 0;
	#endif

	/* Code Section */
	/* If already open - return busy */
	if (s_bLogDeviceOpen) 
	{
		return -EBUSY;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_NAME_LOG DEVICE_OPENED_D_TIMES_FRMT, sCounter++);
	#endif
	
	/* Flagging device as opened */
	s_bLogDeviceOpen = TRUE;

	return DEV_SUCCESS;
}

/*
 * Called when a process, which already opened the log dev file, attempts to read from it.
 * Each call sends another log line to user space
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static ssize_t log_read(struct file *fp, char *buff, size_t length, loff_t *ppos)
{
	/* Static Definition */
	static unsigned int 		sLogRowsDelivered = 0;
	static struct list_head*	pLastDeliveredLogRow;

	/* Vairiable Section */
	log_row_t* 			pLogRow;
	int  				nBytesToCopy = 0;
	char 				strLogRow[LOG_DEV_MAX_LEN + 1];

	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_READ_BEGIN);
	#endif

	/* If first line to deliver */
	if (0 == sLogRowsDelivered)
	{
		/* Setting last delivered as the head */
		pLastDeliveredLogRow = &s_log_list_head;
	}

	/* If all log lines delivered - return 0 signifying end of file */
	if (sLogRowsDelivered == s_uLogLinesCounter) 
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_READ_FINISHED);
		#endif

		/* Resetting the counter */
		sLogRowsDelivered = 0;

		/* Return success */
		return DEV_SUCCESS;
	}

	/* Fetching current log line */
	pLogRow = list_entry(pLastDeliveredLogRow->next, log_row_t, log_rows_list);

	/* Parsing log line fields to firewall rule dev format  */
	if (LOG_DEV_MIN_LEN > 
		sprintf(strLogRow, 
			    LOG_DEV_FORMAT, 
			    pLogRow->timestamp,
			    pLogRow->protocol, 
			    pLogRow->action,   
			    pLogRow->hooknum,  
			    pLogRow->src_ip, 									
			    pLogRow->dst_ip, 	
			    pLogRow->src_port, 
			    pLogRow->dst_port, 
			    pLogRow->reason,   
			    pLogRow->count))
	{
		/* Failed to parse - return error */
		return -EINVAL;
	}

	/* We shall copy the the formatted string */
	nBytesToCopy = strlen(strLogRow);
 	
	/* Validating buffer length is sufficient */
	if (length < nBytesToCopy)
	{
		/* Not enought place - return error */
		return -EINVAL;
	}

	/* Writting to user buffer */
	if (DEV_SUCCESS != 
		copy_to_user(buff, 
					 strLogRow, 
					 nBytesToCopy))
	{
		/* Failed to copy to user buffer */
		return -EIO;
	}

	/* Updating counter */
	++sLogRowsDelivered;

	/* Updating last deliverd log row */
	pLastDeliveredLogRow = pLastDeliveredLogRow->next;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_READ_ENDED);
	#endif

	/* Return number of bytes assigned into the buffer */
	return nBytesToCopy;	
}

/*
 * Called when log dev is released, when there is no process using it.
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static int log_release(struct inode *inode, struct file *file)
{
	/* Variable Definition */
	#ifdef PRINT_DEBUG_MESSAGES
		static int sCounter = 0;
	#endif

	/* Code Section */	
	/* Flagging as closed */
	s_bLogDeviceOpen = FALSE;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_NAME_LOG DEVICE_RELEASED_D_TIMES_FRMT, sCounter++);
	#endif

	return DEV_SUCCESS;
}

void initializeLogStaticVariables(void)
{
	/* Code Section */
	s_bLogDeviceOpen 		 	= FALSE;
	pdLogDevice               	= NULL;

	s_uLogLinesCounter			= 0;
}

EDevReturnValue log_device_init(struct class* pcFirewallClass)
{
	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_INIT_BEGIN);
	#endif

	/* Initialize log variables */
	initializeLogStaticVariables();

	/* Register log char device */
	s_nLogDeviceMajorNumber = register_chrdev(0, DEVICE_NAME_LOG, &fopsLog);
	
	/* Checking major number correctness */
	if (0 > s_nLogDeviceMajorNumber)
	{
		/* Return error */
		return SYSFS_CHAR_DEVICE_REGISTRING_FAILED;
	}

	/* Create sysfs device */
	pdLogDevice = 
		device_create(
			pcFirewallClass, 
			NULL, 
			MKDEV(s_nLogDeviceMajorNumber, MINOR_LOG), 
			NULL, 
			FW_DEVICE_NAME_LOG); 
	
	/* Checking error in sysfs log device */
	if (IS_ERR(pdLogDevice))
	{				
		/* Unregistering char device */		
		unregister_chrdev(s_nLogDeviceMajorNumber, DEVICE_NAME_LOG);

		/* Return error */
		return SYSFS_CHAR_DEVICE_CREATION_FAILED;
	}
	
	/* Create sysfs file attributes	*/
	if (device_create_file(
			pdLogDevice, 
			(const struct device_attribute *)&dev_attr_log_size.attr))
	{
		/* Destroying device */
		device_destroy(pcFirewallClass, MKDEV(s_nLogDeviceMajorNumber, MINOR_LOG));
		
		/* Unregistering char device */		
		unregister_chrdev(s_nLogDeviceMajorNumber, DEVICE_NAME_LOG);

		/* Return error */
		return SYSFS_FILE_CREATION_FAILED;
	}

	/* Create sysfs file attributes	*/
	if (device_create_file(
			pdLogDevice, 
			(const struct device_attribute *)&dev_attr_log_clear.attr))
	{
		/* Removing sysfs file */
		device_remove_file(pdLogDevice, (const struct device_attribute *)&dev_attr_log_size.attr);

		/* Destroying device */
		device_destroy(pcFirewallClass, MKDEV(s_nLogDeviceMajorNumber, MINOR_LOG));
		
		/* Unregistering char device */		
		unregister_chrdev(s_nLogDeviceMajorNumber, DEVICE_NAME_LOG);

		/* Return error */
		return SYSFS_FILE_CREATION_FAILED;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_LOG DEVICE_INIT_ENDED);
	#endif

	/* Return success */
	return DEV_SUCCESS;
}

void log_device_destroy(struct class* pcFirewallClass)
{
	/* Code Section */
	/* Free log */
	freeLog();

	/* Removing sysfs file */
	device_remove_file(pdLogDevice, (const struct device_attribute *)&dev_attr_log_clear.attr);

	/* Removing sysfs file */
	device_remove_file(pdLogDevice, (const struct device_attribute *)&dev_attr_log_size.attr);

	/* Destroying device */
	device_destroy(pcFirewallClass, MKDEV(s_nLogDeviceMajorNumber, MINOR_LOG));
	
	/* Unregistering char device */		
	unregister_chrdev(s_nLogDeviceMajorNumber, DEVICE_NAME_LOG);

	/* Initialize log variables */
	initializeLogStaticVariables();
}

BOOL isMatchingLogRow(fw_packet_info* 	pPacketInfo, log_row_t* pLogRow)
{
	/* Code Section */
	/* If invalid */
	if (!pLogRow)
	{
		return FALSE;
	}

	return (((pPacketInfo->src_ip 	== pLogRow->src_ip) 	&&
			 (pPacketInfo->dst_ip 	== pLogRow->dst_ip) 	&&
			 (pPacketInfo->src_port == pLogRow->src_port) 	&&
			 (pPacketInfo->dst_port == pLogRow->dst_port) 	&&
			 (pPacketInfo->protocol == pLogRow->protocol) 	&&
			 (pPacketInfo->hooknum 	== pLogRow->hooknum) 	&&
			 (pPacketInfo->action 	== pLogRow->action) 	&&
			 (pPacketInfo->reason 	== pLogRow->reason)) ? 
			TRUE : FALSE);
}

/*
 * Inspired by: https://isis.poly.edu/kulesh/stuff/src/klist/	
 */
BOOL updateLogIfExists(fw_packet_info* 	pPacketInfo)
{
	/* Struct Definition */
	log_row_t* 			pCurrentLogRow;
	struct list_head* 	pos;

	/* Code Section */
	/* Going over the log list, 
	   searching for matching row */
	list_for_each(pos, &s_log_list_head){
		/* Fetching current log row entry */
		pCurrentLogRow = list_entry(pos, log_row_t, log_rows_list);

		/* If current log row matches */
		if (isMatchingLogRow(pPacketInfo, pCurrentLogRow))
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_INFO PACKET_EXISTS_IN_LOG);
			#endif

			pCurrentLogRow->timestamp = pPacketInfo->timestamp;
			pCurrentLogRow->count++;

			return TRUE;
		}
	}

	return FALSE;
}

/*
 * Inspired by: https://isis.poly.edu/kulesh/stuff/src/klist/	
 */
void addLogRow(fw_packet_info* 	pPacketInfo)
{
	/* Struct Definition */
	log_row_t* 			pLogRow;

	/* Code Section */
	/* Allocating log row */
	pLogRow = (log_row_t*)kcalloc(1, sizeof(log_row_t), GFP_ATOMIC);

	/* Validating allocated successfully */
	if (!pLogRow)
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_ERR MEMORY_ALLOCATION_FAILED_MSG);
		#endif

		/* Returning */
		return;
	}

	/* Initializing log row fields */		
	pLogRow->timestamp	= pPacketInfo->timestamp;
	pLogRow->protocol	= pPacketInfo->protocol; 
	pLogRow->action		= pPacketInfo->action;   
	pLogRow->hooknum	= pPacketInfo->hooknum;  
	pLogRow->src_ip		= pPacketInfo->src_ip;
	pLogRow->dst_ip		= pPacketInfo->dst_ip;
	pLogRow->src_port	= pPacketInfo->src_port;
	pLogRow->dst_port	= pPacketInfo->dst_port;
	pLogRow->reason		= pPacketInfo->reason;   
	pLogRow->count 		= 1;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO PACKET_ADDED_TO_LOG);
	#endif

	/* Adding log row to list */ 
	list_add(&(pLogRow->log_rows_list), &s_log_list_head);

	/* Updating counter */
	++s_uLogLinesCounter;
}

void logPacket(fw_packet_info* 	pPacketInfo)
{
	/* Code Section */
	/* If nothing to do */
	if (!pPacketInfo)
	{
		return;
	}

	/* No log row matched - adding new log row */
	if (!updateLogIfExists(pPacketInfo))
	{
		addLogRow(pPacketInfo);
	}
}
