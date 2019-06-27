#ifndef _LOG_MODULE_H_
#define _LOG_MODULE_H_

#include "fw.h"
#include "log_dev.h"

/* Define Section */
#define PACKET_ADDED_TO_LOG     " Packet added to log\n"
#define PACKET_EXISTS_IN_LOG    " Packet exists in log\n"

/* Methods Section */
EDevReturnValue log_device_init(struct class* pcFirewallClass);
void log_device_destroy(struct class* pcFirewallClass);

void logPacket(fw_packet_info* 	pPacketInfo);

#endif
