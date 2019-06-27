#ifndef _SYSFS_DEV_H_
#define _SYSFS_DEV_H_

#include "sysfs_dev_msg.h"

/* Define Section */
#define DEBUG											0 
#if DEBUG
#define PRINT_DEBUG_MESSAGES
#endif

/* Sysfs Section */
#define SYSFS_PATH_PREFIX								"/sys/class/"

/* Device Section */
#define DEVICE_PREFIX									"/dev/"

/* Device Permission Bits Section */
#define DEV_PERM_BITS_READ                              S_IRUSR | S_IROTH
#define DEV_PERM_BITS_WRITE                             S_IWUSR | S_IWOTH
#define DEV_PERM_BITS_READ_WRITE                        DEV_PERM_BITS_READ | DEV_PERM_BITS_WRITE

/* Types Max Length */
#define ULONG_MAX_LEN									20	/* strlen(18446744073709551615) */
#define UINT_MAX_LEN									10	/* strlen(4294967295) */
#define USHRT_MAX_LEN									5	/* strlen(65535) */
#define UCHAR_MAX_LEN									3	/* strlen(255) */

/* Types Min Length */
#define NUMERIC_MIN_LEN									1	/* strlen(0) */

/* Types String Format */
#define STRING_FORMAT									"%s"
#define	ULONG_FORMAT									"%lu"
#define UINT_FORMAT										"%u"
#define USHRT_FORMAT									"%hu"
#define UCHAR_FORMAT									"%hhu"
#define CHAR_FORMAT										"%c"
#define DECIMAL_FORMAT                                  "%d"

/* Enum Section */
typedef enum { FALSE, TRUE } BOOL;

/* Enum Section */
#define FOREACH_DEV_RETURN_VALUE(RETURN_VALUE) \
			RETURN_VALUE(DEV_SUCCESS) \
			RETURN_VALUE(USER_CODE_MORE_IS_NULL_ERROR) \
			RETURN_VALUE(USER_CODE_MORE_THAN_ONE_ARG_ERROR) \
			RETURN_VALUE(USER_CODE_UNRECOGNIZED_ERROR) \
			RETURN_VALUE(HOOK_REGISTERING_FAILED) \
			RETURN_VALUE(SYSFS_CHAR_DEVICE_REGISTRING_FAILED) \
			RETURN_VALUE(SYSFS_CLASS_CREATION_FAILED) \
			RETURN_VALUE(SYSFS_CHAR_DEVICE_CREATION_FAILED) \
			RETURN_VALUE(SYSFS_FILE_CREATION_FAILED) \
			RETURN_VALUE(DEV_RETURN_VALUE_NUMBER) \

#ifndef ENUM_GENERATORS
	#define ENUM_GENERATORS
	#define GENERATE_ENUM(ENUM) 	ENUM,
	#define GENERATE_STRING(STRING) #STRING,
#endif

typedef enum EDevReturnValue {
	FOREACH_DEV_RETURN_VALUE(GENERATE_ENUM)
} EDevReturnValue;

#ifdef PRINT_DEBUG_MESSAGES
	static const char* DEV_RETURN_VALUE_STRING[] = {
		FOREACH_DEV_RETURN_VALUE(GENERATE_STRING)
	};
#endif

#endif
