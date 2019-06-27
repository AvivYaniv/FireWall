#include "rules_module.h"

/*
 * Inspired by Reuven Plevinsky;
 * Handling the sysfs code
 * @source: http://course.cs.tau.ac.il//secws16/lectures/
 * 
 */

/* Rules Dev Section */
static BOOL 			s_bRulesDeviceOpen 					= FALSE;
static int              s_nRuleDeviceMajorNumber;
static struct device*   pdRulesDevice               		= NULL;

static size_t 			s_sTotalBytesWrittenToBuffer 		= 0;
static char*			s_pRulesFromUserWriteBuffer			= NULL;

/* Rules character driver functions */
static int     rules_open(struct inode *, struct file *);
static ssize_t rules_read(struct file *, char *, size_t, loff_t *);
static ssize_t rules_write(struct file *, const char *, size_t, loff_t *);
static int     rules_release(struct inode *, struct file *);

static struct file_operations fopsRules = {
	.owner 		= THIS_MODULE,
	.open 		= rules_open,
	.read 		= rules_read,
	.write 		= rules_write,
	.release 	= rules_release,
};

/* Rules Section */
static BOOL				s_bIsActive							= FALSE;
static unsigned int		s_uRulesCounter						= 0;
static rule_t 			s_arrRules[MAX_RULES];

/* Methods Section */
/* Attributes Section */
/* Active Attribute Section */
ssize_t get_is_active(struct device *dev, struct device_attribute *attr, char *buf)
{
	/* Variable Section */
    ssize_t sstTotalCharsWritten = 0;
	char strActiveCode[RULES_ACTIVE_STATUS_LENGTH + 1];

	/* Code Section */
	strActiveCode[0] = 
		s_bIsActive ? 
			RULES_ACTIVE_STATUS_CODE :
			RULES_INACTIVE_STATUS_CODE;
	strActiveCode[RULES_ACTIVE_STATUS_LENGTH] = '\0';

    /* Writing is active */
    sstTotalCharsWritten = scnprintf(buf, PAGE_SIZE, STRING_FORMAT, strActiveCode);

    /* If error occured */
    if (0 >= sstTotalCharsWritten)
    {
		#ifdef PRINT_DEBUG_MESSAGES
        	printk(KERN_ERR FW_DEVICE_NAME_RULES WRITTING_SYSFS_FAILED_MSG);
		#endif
    }

	return sstTotalCharsWritten;
}

ssize_t set_is_active(struct device *dev, struct device_attribute *attr, const char *buf, size_t count)
{
	/* Variable Section */
	char cUserCode;

	/* Code Section */
	/* If buffer is empty */
    if (NULL == buf)
    {
        return -USER_CODE_MORE_IS_NULL_ERROR;    
    }
    /* If more than one argument */
    else if (1 != count)    
    {		
        return -USER_CODE_MORE_THAN_ONE_ARG_ERROR;
    }
    /* Else, checking user code */
    else
    {
        cUserCode = buf[0];

        /* Switch case checking user code */
        switch (cUserCode)        
        {
            /* In case it's active code */
            case (RULES_ACTIVE_STATUS_CODE):
                {
                    s_bIsActive = TRUE;

					#ifdef PRINT_DEBUG_MESSAGES
						printk(KERN_INFO FW_DEVICE_NAME_RULES " " ACTIVATE_ACTION "\n");
					#endif

                    /* Exitting switch-case */
                    break;
                }
			/* In case it's inactive code */
            case (RULES_INACTIVE_STATUS_CODE):
                {
                    s_bIsActive = FALSE;

					#ifdef PRINT_DEBUG_MESSAGES
						printk(KERN_INFO FW_DEVICE_NAME_RULES " " DEACTIVATE_ACTION "\n");
					#endif

                    /* Exitting switch-case */
                    break;
                }
            /* Default case, unrecognized code */
            default:
                {
					#ifdef PRINT_DEBUG_MESSAGES
						printk(KERN_ERR FW_DEVICE_NAME_RULES READING_SYSFS_FAILED_MSG);
					#endif

                    /* Returning error */
                    return -USER_CODE_UNRECOGNIZED_ERROR;
                }
        }
    }
	
    /* Returning bytes read counter */
	return count;
}

static DEVICE_ATTR(active, DEV_PERM_BITS_READ_WRITE, get_is_active, set_is_active);

/* Rules size Attribute Section */
ssize_t read_rules_size(struct device *dev, struct device_attribute *attr, char *buf)
{
	/* Variable Section */
    ssize_t sstTotalCharsWritten = 0;

	/* Code Section */
    /* Writing is active */
    sstTotalCharsWritten = 
		scnprintf(buf, 
				  PAGE_SIZE, 
				  UINT_FORMAT, 
				  s_uRulesCounter);

    /* If error occured */
    if (0 >= sstTotalCharsWritten)
    {
		#ifdef PRINT_DEBUG_MESSAGES
        	printk(KERN_ERR FW_DEVICE_NAME_RULES WRITTING_SYSFS_FAILED_MSG);
		#endif
    }

	return sstTotalCharsWritten;
}

static DEVICE_ATTR(rules_size, DEV_PERM_BITS_READ, read_rules_size, NULL);

/* Device Read-Write Section */
/*
 * Called when rules device is opened
 * 
 * Inspired by: https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 */
static int rules_open(struct inode *inode, struct file *filp)
{
	/* Variable Definition */
	#ifdef PRINT_DEBUG_MESSAGES
		static int sCounter = 0;
	#endif

	/* Code Section */
	/* If already open - return busy */
	if (s_bRulesDeviceOpen) 
	{
		return -EBUSY;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_NAME_RULES DEVICE_OPENED_D_TIMES_FRMT, sCounter++);
	#endif
	
	/* Flagging device as opened */
	s_bRulesDeviceOpen = TRUE;

	return DEV_SUCCESS;
}

/*
 * Called when a process, which already opened the rules dev file, attempts to read from it.
 * Each call sends another rule to user space
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static ssize_t rules_read(struct file *fp, char *buff, size_t length, loff_t *ppos)
{
	/* Static Definition */
	static unsigned int sRulesDelivered = 0;

	/* Vairiable Section */
	rule_t* pRule;
	int  	nBytesToCopy = 0;
	char 	strRule[RULE_DEV_MAX_LEN + 1];

	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_READ_BEGIN);
	#endif

	/* If all rules delivered - return 0 signifying end of file */
	if (sRulesDelivered == s_uRulesCounter) 
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_READ_FINISHED);
		#endif

		/* Resetting the counter */
		sRulesDelivered = 0;

		/* Return success */
		return DEV_SUCCESS;
	}

	/* Fetching current rule */
	pRule = &(s_arrRules[sRulesDelivered]);

	/* Parsing rule fields to firewall rule dev format  */
	if (RULE_DEV_MIN_LEN > 
		sprintf(strRule, 
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
			    pRule->action))
	{
		/* Failed to parse - return error */
		return -EINVAL;
	}

	/* We shall copy the the formatted string */
	nBytesToCopy = strlen(strRule);
 	
	/* Validating buffer length is sufficient */
	if (length < nBytesToCopy)
	{
		/* Not enought place - return error */
		return -EINVAL;
	}

	/* Writting to user buffer */
	if (DEV_SUCCESS != 
		copy_to_user(buff, 
					 strRule, 
					 nBytesToCopy))
	{
		/* Failed to copy to user buffer */
		return -EIO;
	}

	/* Updating counter */
	++sRulesDelivered;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_READ_ENDED);
	#endif

	/* Return number of bytes assigned into the buffer */
	return nBytesToCopy;	
}

void freeRulesFromUserWriteBuffer(void)
{
	/* Resetting counter */	
	s_sTotalBytesWrittenToBuffer = 0;

	if (s_pRulesFromUserWriteBuffer)
	{
		kfree(s_pRulesFromUserWriteBuffer);
		s_pRulesFromUserWriteBuffer = NULL;
	}
}

/*
 * Called when a process writes to rules dev file
 * Each call writes data from user space
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static ssize_t rules_write(struct file *fp, const char *buff, size_t length, loff_t *ppos)
{
	/* Variable Definition */
	long lFreeSpaceToCopy = 0;
	long lBytesToCopy = 0;

	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_WRITE_BEGIN);
	#endif

	/* Invalid length given */
	if (0 >= length)
	{
		/* Return failure */
		return -EINVAL;
	}

	/* First call in write session - buffer uninitialized */
	if (!s_pRulesFromUserWriteBuffer)
	{		
		/* Allocate buffer to copy data from user space */
		s_pRulesFromUserWriteBuffer = (char*)kcalloc(ALL_RULES_DEV_MAX_LEN, sizeof(char), GFP_ATOMIC);

		/* If wasn't allocated - not enough memory */
		if (!s_pRulesFromUserWriteBuffer)
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
		(ALL_RULES_DEV_MAX_LEN - 1 - s_sTotalBytesWrittenToBuffer);

	/* No more free space - reached invalid state */
	if (0 > lFreeSpaceToCopy)
	{
		/* Free rules write buffer */
		freeRulesFromUserWriteBuffer();

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
			s_pRulesFromUserWriteBuffer + s_sTotalBytesWrittenToBuffer,
			buff,
			lBytesToCopy))
	{
		/* Free rules write buffer */
		freeRulesFromUserWriteBuffer();

		/* Return failure */
		return -EIO;
	}

	/* Updating toatl bytes counter */
	s_sTotalBytesWrittenToBuffer += lBytesToCopy;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_WRITE_ENDED);
	#endif

	/* Return number of bytes copyied */
	return lBytesToCopy;
}

BOOL isRuleExists(rule_t arrRules[], const unsigned int uLength, char* rule_name)
{
	int i;
	
	for(i = 0; uLength > i; ++i)
	{
		if (!strcmp(arrRules[i].rule_name, rule_name))
		{
			return TRUE;
		}
	}

	return FALSE;
}

BOOL validateDirection(int direction)
{
	switch (direction)
	{
		case DIRECTION_IN:
		case DIRECTION_OUT:
		case DIRECTION_ANY:
		{
			return TRUE;
		}
		default:
		{
			return FALSE;
		}
	}
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

BOOL validatePrefix(unsigned int	prefix_mask,
					unsigned char   prefix_size)
{
	return ((32 >= prefix_size) && 
			(toPrefixMask(prefix_size) == prefix_mask)) ? 
			TRUE : 
			FALSE;
}

BOOL validateProtocol(unsigned char protocol)
{
	switch (protocol)
	{
		case PROT_ICMP:
		case PROT_TCP:
		case PROT_UDP:
		case PROT_OTHER:
		case PROT_ANY:
		{
			return TRUE;
		}
		default:
		{
			return FALSE;
		}
	}
}

BOOL validateAck(int ack)
{
	switch (ack)
	{
		case ACK_NO:
		case ACK_YES:
		case ACK_ANY:
		{
			return TRUE;
		}
		default:
		{
			return FALSE;
		}
	}
}

BOOL validateAction(unsigned char action)
{
	switch (action)
	{
		case NF_ACCEPT:
		case NF_DROP:		
		{
			return TRUE;
		}
		default:
		{
			return FALSE;
		}
	}
}

void addRuleToArray(rule_raw_t* pRuleRaw)
{
	/* Varaible Section */
	rule_t* pRule;
	
	/* Code Section */
	/* Fetching rule */
	pRule = &(s_arrRules[s_uRulesCounter]);

	/* Copying field by field */
	strncpy(pRule->rule_name, pRuleRaw->rule_name, RULE_DEV_MAX_RULE_NAME_LEN);
	pRule->direction 		= (direction_t)pRuleRaw->direction;	
	pRule->src_ip 			= pRuleRaw->src_ip;
	pRule->src_prefix_mask 	= pRuleRaw->src_prefix_mask;
	pRule->src_prefix_size 	= pRuleRaw->src_prefix_size;
	pRule->dst_ip 			= pRuleRaw->dst_ip;
	pRule->dst_prefix_mask 	= pRuleRaw->dst_prefix_mask;
	pRule->dst_prefix_size 	= pRuleRaw->dst_prefix_size;
	pRule->src_port 		= pRuleRaw->src_port;
	pRule->dst_port 		= pRuleRaw->dst_port;
	pRule->protocol 		= pRuleRaw->protocol;
	pRule->ack 				= (ack_t)pRuleRaw->ack;
	pRule->action 			= pRuleRaw->action;
	
	/* Updating counter */
	s_uRulesCounter++;
}

BOOL validateRule(rule_raw_t* pRuleRaw)
{
	/* Ip & Port - all values are valid */
	return (!validateDirection(pRuleRaw->direction) ||
			!validatePrefix(pRuleRaw->src_prefix_mask, pRuleRaw->src_prefix_size) ||
			!validatePrefix(pRuleRaw->dst_prefix_mask, pRuleRaw->dst_prefix_size) ||
			!validateProtocol(pRuleRaw->protocol) ||
			!validateAck(pRuleRaw->ack) ||
			!validateAction(pRuleRaw->action)) ? FALSE : TRUE;
}

BOOL parseSingleDevRule(char* strSingleRuleDevFormat)
{
	/* Variable Definition */
	size_t sLength;
	rule_raw_t rRuleRaw;

	/* Code Section */
	/* If null or reached maximal rules number */
	if ((NULL == strSingleRuleDevFormat) ||
		(RULES_MAX_NUMBER <= s_uRulesCounter))
	{
		return FALSE;
	}
	
	sLength = strnlen(strSingleRuleDevFormat, RULE_DEV_MAX_LEN + 1);

	/* If rule dev format lenght is zero */
	if (0 == sLength)
	{
		return FALSE;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_PARSING_FRMT, strSingleRuleDevFormat);
	#endif

	/* If rule dev format lenght exceeds maximal length */
	if (RULE_DEV_MAX_LEN < sLength)
	{
		return FALSE;
	}
	
	/* Parsing to raw rule format */
	if (FIELDS_IN_RULE_DEV != 
		sscanf(strSingleRuleDevFormat,
			   RULE_DEV_FORMAT,
			   rRuleRaw.rule_name, 
			   &rRuleRaw.direction, 
			   &rRuleRaw.src_ip, 
			   &rRuleRaw.src_prefix_mask, 
			   &rRuleRaw.src_prefix_size, 
			   &rRuleRaw.dst_ip, 
			   &rRuleRaw.dst_prefix_mask, 
			   &rRuleRaw.dst_prefix_size, 
			   &rRuleRaw.src_port, 
			   &rRuleRaw.dst_port, 
			   &rRuleRaw.protocol, 
			   &rRuleRaw.ack,
			   &rRuleRaw.action))
	{
		return FALSE;
	}

	/* If rule name already exists */
	if (isRuleExists(s_arrRules, s_uRulesCounter, rRuleRaw.rule_name))
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printk(KERN_INFO DEVICE_PARSED_DATA_ALREADY_EXISTS);
		#endif

		return FALSE;
	}

	/* Validating rule */	
	if (!validateRule(&rRuleRaw))
	{
		return FALSE;
	}

	/* Adding validated rule to array */
	addRuleToArray(&rRuleRaw);

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_PARSED_SUCCESSFULLY);
	#endif

	/* Return Success */
	return TRUE;
}

void parseRulesFromWriteBuffer(void)
{
	/* Variable Section */
	char* strSingleRuleDevFormat;
	char* pRulesFromUserWriteBuffer;
	BOOL bParsed;

	/* Code Section */
	/* Copying pointer so strsep will overwrite */	
	pRulesFromUserWriteBuffer = 
		s_pRulesFromUserWriteBuffer;

	/* Going over the dev formatted rules */
	while ((NULL != 
		    (strSingleRuleDevFormat = 
		   		strsep(&pRulesFromUserWriteBuffer, 
				   	   RULE_DEV_ITEM_SEPERATOR))))
	{
		/* If reached maximal rules number */
		if (RULES_MAX_NUMBER <= s_uRulesCounter)
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR DEVICE_RECIVED_TOO_MUCH_DATA_ERROR);
			#endif
			
			break;
		}

		/* If rule dev format lenght is zero */
		if (0 == strnlen(strSingleRuleDevFormat, RULE_DEV_MAX_LEN + 1))
		{
			continue;
		}

		/* parsing single dev formatted rule */
		bParsed = parseSingleDevRule(strSingleRuleDevFormat);
		
		#ifdef PRINT_DEBUG_MESSAGES
			if (!bParsed)
			{
				printk(KERN_ERR DEVICE_FAILED_PARSE_DATA_ERROR);
			}
		#endif
	}
}

void parseUserCode(void)
{
	/* Code Section */
	switch (s_pRulesFromUserWriteBuffer[0])
	{
		case CLEAR_RULES_CODE:
		{
			/* Resetting rules counter */
			s_uRulesCounter = 0;

			break;
		}

		default:
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR FW_DEVICE_NAME_RULES DEVICE_FAILED_PARSE_USER_CODE_ERROR);
			#endif

			break;
		}
	}
}

/*
 * Called when rules dev is released, when there is no process using it.
 * Handels data written do rules dev
 * 
 * Inspired by: 
 * 		https://www.tldp.org/LDP/lkmpg/2.4/html/c577.htm
 * 		https://gist.github.com/ksvbka/6d6a02c6e8dddea2e0f2
 * 		http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/
 */
static int rules_release(struct inode *inode, struct file *file)
{
	/* Variable Definition */
	#ifdef PRINT_DEBUG_MESSAGES
		static int sCounter = 0;
	#endif

	/* Code Section */
	/* If closing after write - handle data */
	if (s_sTotalBytesWrittenToBuffer)
	{
		/* If no data to handle */
		if (!s_pRulesFromUserWriteBuffer)
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_ERR FW_DEVICE_NAME_RULES DEVICE_WRITE_FINISHED_NO_DATA_ERROR);
			#endif
		}
		/* Else, handling data */
		else
		{
			#ifdef PRINT_DEBUG_MESSAGES
				printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_WRITE_FINISHED);
			#endif

			/* If entered user code */
			if (1 == s_sTotalBytesWrittenToBuffer)
			{
				parseUserCode();
			}
			/* Else, parsing user data */
			else
			{
				/* Parse rules from write buffer */
				parseRulesFromWriteBuffer();
			}

			/* Free the write buffer */
			freeRulesFromUserWriteBuffer();
		}
	}
	
	/* Flagging as closed */
	s_bRulesDeviceOpen = FALSE;

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO DEVICE_NAME_RULES DEVICE_RELEASED_D_TIMES_FRMT, sCounter++);
	#endif

	return DEV_SUCCESS;
}

void initializeRulesStaticVariables(void)
{
	/* Code Section */
	s_bRulesDeviceOpen 					= FALSE;	
	pdRulesDevice               		= NULL;

	s_sTotalBytesWrittenToBuffer 		= 0;
	s_pRulesFromUserWriteBuffer			= NULL;

	s_bIsActive							= FALSE;
	s_uRulesCounter						= 0;
}

EDevReturnValue rules_device_init(struct class* pcFirewallClass)
{
	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_INIT_BEGIN);
	#endif

	/* Initialize rules variables */
	initializeRulesStaticVariables();

	/* Register rules char device */
	s_nRuleDeviceMajorNumber = register_chrdev(0, DEVICE_NAME_RULES, &fopsRules);
	
	/* Checking major number correctness */
	if (0 > s_nRuleDeviceMajorNumber)
	{
		/* Return error */
		return SYSFS_CHAR_DEVICE_REGISTRING_FAILED;
	}

	/* Create sysfs device */
	pdRulesDevice = 
		device_create(
			pcFirewallClass, 
			NULL, 
			MKDEV(s_nRuleDeviceMajorNumber, MINOR_RULES), 
			NULL, 
			FW_DEVICE_NAME_RULES); 
	
	/* Checking error in sysfs rule device */
	if (IS_ERR(pdRulesDevice))
	{				
		/* Unregistering char device */		
		unregister_chrdev(s_nRuleDeviceMajorNumber, DEVICE_NAME_RULES);

		/* Return error */
		return SYSFS_CHAR_DEVICE_CREATION_FAILED;
	}
	
	/* Create sysfs file attributes	*/
	if (device_create_file(
			pdRulesDevice, 
			(const struct device_attribute *)&dev_attr_active.attr))
	{
		/* Destroying device */
		device_destroy(pcFirewallClass, MKDEV(s_nRuleDeviceMajorNumber, MINOR_RULES));
		
		/* Unregistering char device */		
		unregister_chrdev(s_nRuleDeviceMajorNumber, DEVICE_NAME_RULES);

		/* Return error */
		return SYSFS_FILE_CREATION_FAILED;
	}

	/* Create sysfs file attributes	*/
	if (device_create_file(
			pdRulesDevice, 
			(const struct device_attribute *)&dev_attr_rules_size.attr))
	{
		/* Removing sysfs file */
		device_remove_file(pdRulesDevice, (const struct device_attribute *)&dev_attr_active.attr);

		/* Destroying device */
		device_destroy(pcFirewallClass, MKDEV(s_nRuleDeviceMajorNumber, MINOR_RULES));
		
		/* Unregistering char device */		
		unregister_chrdev(s_nRuleDeviceMajorNumber, DEVICE_NAME_RULES);

		/* Return error */
		return SYSFS_FILE_CREATION_FAILED;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO FW_DEVICE_NAME_RULES DEVICE_INIT_ENDED);
	#endif

	/* Return success */
	return DEV_SUCCESS;
}

void rules_device_destroy(struct class* pcFirewallClass)
{
	/* Code Section */
	/* Free write buffer memory */
	freeRulesFromUserWriteBuffer();

	/* Removing sysfs file */
	device_remove_file(pdRulesDevice, (const struct device_attribute *)&dev_attr_rules_size.attr);

	/* Removing sysfs file */
	device_remove_file(pdRulesDevice, (const struct device_attribute *)&dev_attr_active.attr);

	/* Destroying device */
	device_destroy(pcFirewallClass, MKDEV(s_nRuleDeviceMajorNumber, MINOR_RULES));
	
	/* Unregistering char device */		
	unregister_chrdev(s_nRuleDeviceMajorNumber, DEVICE_NAME_RULES);

	/* Initialize rules variables */
	initializeRulesStaticVariables();
}

BOOL isMatchingProtocol(prot_t	tPacketProtocol, 
						prot_t	tRuleProtocol)
{
	return (((tPacketProtocol	== tRuleProtocol) ||
			 (PROT_ANY			== tRuleProtocol)) ? 
			 TRUE : FALSE);
}

BOOL isMatchingIP(__be32		uPacketIP, 
				  __be32		uRulePrefixMask,
				  __be32	 	uRuleIP)
{
	return (((uPacketIP & uRulePrefixMask) == (uRuleIP & uRulePrefixMask)) ? 
			 TRUE : FALSE);
}

BOOL isMatchingPort(__be16 		uPacketPort, 
					__be16		uRulePort)
{
	return (((uPacketPort 		== uRulePort) ||
			 (PORT_ANY			== uRulePort) ||
			 ((PORT_ABOVE_1023	== uRulePort) && (PORT_ABOVE_1023 < uPacketPort))) ? 
			TRUE : FALSE);
}

BOOL isMatchingDirection(direction_t 	tPacketDirection, 
						 direction_t	tRuleDirection)
{
	return (((tPacketDirection 	== tRuleDirection) ||
			 (DIRECTION_ANY		== tPacketDirection) ||
			 (DIRECTION_ANY		== tRuleDirection)) ? 
			TRUE : FALSE);
}

BOOL isMatchingAck(ack_t 	tPacketAck, 
				   ack_t	tRuleAck)
{
	return (((tPacketAck 		== tRuleAck) ||
			 (ACK_ANY			== tRuleAck)) ? 
			TRUE : FALSE);
}

verdict_t getRuleVerdict(fw_packet_info* pPacketInfo,
						 rule_t*		 pRule)
{
	/* Variable Section */
	verdict_t			vVerdict = VERDICT_NONE;

	/* Code Section */
	/* If packet match with rule */
	if (isMatchingProtocol((prot_t)pPacketInfo->protocol, (prot_t)pRule->protocol)	&&
		isMatchingIP(pPacketInfo->src_ip, pRule->src_prefix_mask, pRule->src_ip)	&&
		isMatchingIP(pPacketInfo->dst_ip, pRule->dst_prefix_mask, pRule->dst_ip) 	&&
		isMatchingDirection(pPacketInfo->direction, pRule->direction))
	{
		/* If rule isn't about TCP / UDP */
		if ((PROT_TCP != pRule->protocol) && 
			(PROT_UDP != pRule->protocol))
		{
			vVerdict = (verdict_t)pRule->action;		
		}
		/* Else, protocol is TCP / UDP */
		else
		{
			/* If ports match as well */
			if (isMatchingPort(pPacketInfo->src_port, pRule->src_port) && 
				isMatchingPort(pPacketInfo->dst_port, pRule->dst_port))
			{
				/* If it's UDP or TCP ack match as well */
				if (( PROT_UDP == pPacketInfo->protocol) ||
					((PROT_TCP == pPacketInfo->protocol) &&
					 isMatchingAck(pPacketInfo->ack, pRule->ack)))
				{
					vVerdict = (verdict_t)pRule->action;
				}
			}
		}
	}

	/* Return value */
	return vVerdict;
}

int setPacketVerdictByRules(fw_packet_info* pPacketInfo)
{
	/* Variable Section */
	verdict_t			vVerdict;
	unsigned int		uMatchingRuleIndex;

	/* Code Section */
	/* Going over the rules searching for matching rule */
	for (uMatchingRuleIndex = 0; s_uRulesCounter > uMatchingRuleIndex; ++uMatchingRuleIndex)
	{
		/* If rule matches */
		if (VERDICT_NONE != (vVerdict = getRuleVerdict(pPacketInfo, &s_arrRules[uMatchingRuleIndex])))
		{
			/* Setting packet verdict */
			pPacketInfo->action = vVerdict;

			/* Positive rule index will symbolize the rule matched */
			pPacketInfo->reason = uMatchingRuleIndex;

			/* Returning rule number */
			return uMatchingRuleIndex;
		}
	}

	/* Return value */
	return RULE_NOT_MATCH;
}

void setPacketVerdict(fw_packet_info* 	pPacketInfo)
{
    /* Code Section */
	/* If noting to check */
	if (!pPacketInfo)
	{
		return;
	}

	/* If FireWall is inactice */
	if (!s_bIsActive)
	{
		pPacketInfo->action = NF_ACCEPT;
		pPacketInfo->reason = REASON_FW_INACTIVE;

		return;
	}

	/* If no matching rule found */
	if (0 > setPacketVerdictByRules(pPacketInfo))
	{
		pPacketInfo->action = NF_ACCEPT;
		pPacketInfo->reason = REASON_NO_MATCHING_RULE;
	}
}
