#ifndef _RULES_MODULE_H_
#define _RULES_MODULE_H_

#include "fw.h"
#include "packet_verdict.h"
#include "rules_dev.h"

/* Define Section */
/* Messages */
#define SETTING_PACKET_VERDICT_BY_RULES_TABLE      " Setting packet verdict by rules table.\n"

/* Methods Section */
EDevReturnValue rules_device_init(struct class* pcFirewallClass);
void rules_device_destroy(struct class* pcFirewallClass);

BOOL isFirewallActive(void);
void setPacketVerdictByRules(fw_packet_info* 	pPacketInfo);

#endif
