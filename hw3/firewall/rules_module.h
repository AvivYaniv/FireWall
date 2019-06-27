#ifndef _RULES_MODULE_H_
#define _RULES_MODULE_H_

#include "fw.h"
#include "rules_dev.h"

/* Define Section */
#define RULE_NOT_MATCH	(-1)

/* Enum Section */
typedef enum {
	VERDICT_NONE      			 =  RULE_NOT_MATCH,
	VERDICT_ALLOW				 =  NF_ACCEPT,
	VERDICT_BLOCK           	 =  NF_DROP,
} verdict_t;

EDevReturnValue rules_device_init(struct class* pcFirewallClass);
void rules_device_destroy(struct class* pcFirewallClass);

void setPacketVerdict(fw_packet_info* 	pPacketInfo);

#endif
