#include "fw.h"
#include "firewall_module.h"

/*
 * Inspired by Reuven Plevinsky;
 * Kernel Module
 * @source: http://course.cs.tau.ac.il/secws16/lectures/
 * 
 */

/* Module Description */
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("FireWall");
MODULE_AUTHOR("Aviv Yaniv");

/* Messages */
#define MODULE_FIREWALL_LOAD_STARTED_MSG				"Module FireWall Load Started...\n"
#define MODULE_FIREWALL_LOAD_FINISHED_MSG				"Module FireWall Load Finished!\n"

#define MODULE_FIREWALL_EXIT_STARTED_MSG				"Module FireWall Exit Started...\n"
#define MODULE_FIREWALL_EXIT_FINISHED_MSG				"Module FireWall Exit Finished!\n"

#define PACKET_BLOCKED_MSG								"*** packet blocked ***\n"
#define PACKET_PASSED_MSG								"*** packet passed ***\n"

/* Enum Section */
#define FOREACH_RETURN_VALUE(RETURN_VALUE) \
			RETURN_VALUE(SUCCESS)	\
			RETURN_VALUE(FAILED_INIT_SYSFS_RULES_DEVICE) \
			RETURN_VALUE(FAILED_INIT_SYSFS_LOG_DEVICE) \
			RETURN_VALUE(RETURN_VALUE_NUMBER)   \

#ifndef ENUM_GENERATORS
	#define ENUM_GENERATORS
	#define GENERATE_ENUM(ENUM) 	ENUM,
	#define GENERATE_STRING(STRING) #STRING,
#endif

typedef enum EReturnValue {
    FOREACH_RETURN_VALUE(GENERATE_ENUM)
} EReturnValue;

#ifdef PRINT_DEBUG_MESSAGES
	static const char *RETURN_VALUE_STRING[] = {
		FOREACH_RETURN_VALUE(GENERATE_STRING)
	};
#endif

/* Struct Section */

/* Sysfs & Devices Section */
static struct class*    pcFirewallClass                = NULL;

/**
 * Description: Initializing firewall sysfs char devices
 *
 * Parameters: None
 *
 * Return value: DEV_SUCCESS, which is zero for success, negative number for failure
 *
 */
static EDevReturnValue firewallSysfsOpen(void)
{
	/* Variable Definition */
	EDevReturnValue drvReturnValue;

	/* Code Section */		
	/* Create sysfs class */
	pcFirewallClass = class_create(THIS_MODULE, CLASS_NAME);

	/* Checking error in sysfs class */
	if (IS_ERR(pcFirewallClass))
	{
		/* Return error */
		return SYSFS_CLASS_CREATION_FAILED;
	}
	
	/* Create sysfs rule device */
	drvReturnValue = rules_device_init(pcFirewallClass);
	
	/* Checking error in sysfs rule device */
	if (DEV_SUCCESS != drvReturnValue)
	{
		/* Destroying class */
		class_destroy(pcFirewallClass);

		/* Return error */
		return drvReturnValue;
	}

	/* Create sysfs connection table device */
	drvReturnValue = connection_table_device_init(pcFirewallClass);
	
	/* Checking error in sysfs connection table device */
	if (DEV_SUCCESS != drvReturnValue)
	{
		/* Destroying rule device */
		rules_device_destroy(pcFirewallClass);

		/* Destroying class */
		class_destroy(pcFirewallClass);

		/* Return error */
		return drvReturnValue;
	}
	
	/* Create sysfs log device */
	drvReturnValue = log_device_init(pcFirewallClass);
	
	/* Checking error in sysfs rule device */
	if (DEV_SUCCESS != drvReturnValue)
	{
		/* Destroying connection table device */
		connection_table_device_destroy(pcFirewallClass);

		/* Destroying rule device */
		rules_device_destroy(pcFirewallClass);

		/* Destroying class */
		class_destroy(pcFirewallClass);

		/* Return error */
		return drvReturnValue;
	}

	/* Return success */
	return DEV_SUCCESS;
}

/**
 * Description: Exitting firewall sysfs char device
 *
 * Parameters: None
 *
 * Return value: None
 *
 */
void firewallSysfsClose(void)
{
	/* Code Section */
	/* Destroying connection table device */
	connection_table_device_destroy(pcFirewallClass);

	/* Destroying rule device */
	rules_device_destroy(pcFirewallClass);

	/* Destroying log device */
	log_device_destroy(pcFirewallClass);

	/* Destroying class */
	class_destroy(pcFirewallClass);
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
void printReturnValue(EDevReturnValue eReturnValue)
{
	#ifdef PRINT_DEBUG_MESSAGES	
		if (DEV_SUCCESS == eReturnValue)
		{
			printk(KERN_INFO STRING_NEW_LINE_FORMAT, DEV_RETURN_VALUE_STRING[eReturnValue]);
		}
		else
		{
			printk(KERN_ERR STRING_NEW_LINE_FORMAT, DEV_RETURN_VALUE_STRING[eReturnValue]);
		}
		
	#endif
}

/* Module Functions Section */
/**
 * Description: FireWall module init function
 * 				Opening sysfs char devices
 * 				Registering hooks
 *
 * Parameters: None
 *
 * Return value:
 *		0			-	For success
 *		Negative	-	If sysfs, char devices, or hook registaration failed
 */
static int __init firewall_init_function(void) {
	/* Variable Definition */
	EDevReturnValue result;

	/* Code Section */
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO MODULE_FIREWALL_LOAD_STARTED_MSG);
	#endif

	result = DEV_SUCCESS;

	/* Opening sysfs char devices */	
	if ((result = firewallSysfsOpen()))
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printReturnValue(result);
		#endif

		return result;
	}

	/* Initializing firewall hooks */
	if ((result = registerHooks()))
	{
		#ifdef PRINT_DEBUG_MESSAGES
			printReturnValue(result);
		#endif

		/* Closing the sysfs char device */	
		firewallSysfsClose();

		return result;
	}

	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO MODULE_FIREWALL_LOAD_FINISHED_MSG);
	#endif
	return result;
}

/**
 * Description: FireWall module exit function
 *
 * Parameters: None
 *
 * Return value: None
 */
static void __exit firewall_exit_function(void) {
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO MODULE_FIREWALL_EXIT_STARTED_MSG);
	#endif

	/* Closing the sysfs char device */	
	firewallSysfsClose();

	/* Unregister hooks */
	unregisterHooks();
	
	#ifdef PRINT_DEBUG_MESSAGES
		printk(KERN_INFO MODULE_FIREWALL_EXIT_FINISHED_MSG);
	#endif
}

/* Define Macros Section */
module_init(firewall_init_function);
module_exit(firewall_exit_function);
