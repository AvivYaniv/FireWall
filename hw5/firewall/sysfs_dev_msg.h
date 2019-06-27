#ifndef _SYSFS_DEV_MSG_H_
#define _SYSFS_DEV_MSG_H_

/* Define Section */
/* Messages */
#define DEVICE_INIT_BEGIN						        " Device init begin!\n"
#define DEVICE_INIT_ENDED						        " Device init end!\n"

#define DEVICE_OPENED_D_TIMES_FRMT						" Device opened %d times.\n"

#define DEVICE_READ_BEGIN								" Device read begin!\n"
#define DEVICE_READ_ENDED								" Device read end!\n"
#define DEVICE_READ_FINISHED							" Device read finished!\n"

#define DEVICE_WRITE_BEGIN								" Device write begin!\n"
#define DEVICE_WRITE_ENDED								" Device write end!\n"
#define DEVICE_WRITE_FINISHED							" Device write finished!\n"

#define DEVICE_PARSED_DATA_ALREADY_EXISTS               " Device parsed data already exists!\n"
#define DEVICE_PARSING_FRMT                             " Device parsing: %s\n"
#define DEVICE_PARSED_SUCCESSFULLY                      " Device parsed successfully\n"

#define DEVICE_WRITE_FINISHED_NO_DATA_ERROR				" Device write finished no data!\n"
#define DEVICE_FAILED_PARSE_USER_CODE_ERROR				" Device failed parse user code!\n"
#define DEVICE_FAILED_PARSE_DATA_ERROR			        " Device failed parse data!\n"
#define DEVICE_RECIVED_TOO_MUCH_DATA_ERROR			    " Device recived too much data!\n"

#define DEVICE_DATA_IS_INVALID_ERROR			        " Device got invalid data!\n"
#define DEVICE_DATA_LENGTH_INVALID_ERROR			    " Device got data of invalid length!\n"

#define DEVICE_RELEASED_D_TIMES_FRMT					" Device released %d times.\n"

#define DEVICE_DATA_CLEARED                             " Device data cleared.\n"

#define WRITTING_SYSFS_FAILED_MSG					    " Writting to sysfs has faild!\n"
#define READING_SYSFS_FAILED_MSG					    " Reading to sysfs has faild!\n"

#endif
