#ifndef _SYSFS_DEV_H_
#define _SYSFS_DEV_H_

/* Define Section */
/* Messages */
#define DEVICE_OPENED_D_TIMES_FRMT						" Device opened %d times.\n"

#define DEVICE_READ_BEGIN								" Device read begin!\n"
#define DEVICE_READ_ENDED								" Device read end!\n"
#define DEVICE_READ_FINISHED							" Device read finished!\n"

#define DEVICE_WRITE_BEGIN								" Device write begin!\n"
#define DEVICE_WRITE_ENDED								" Device write end!\n"
#define DEVICE_WRITE_FINISHED							" Device write finished!\n"

#define DEVICE_RELEASED_D_TIMES_FRMT					" Device released %d times.\n"

/* Sysfs Section */
#define SYSFS_PATH_PREFIX								"/sys/class/"

/* Device Section */
#define DEVICE_PREFIX									"/dev/"

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

#endif
