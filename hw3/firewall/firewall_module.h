#ifndef _FIREWALL_MODULE_H_
#define _FIREWALL_MODULE_H_

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>

#include "fw.h"
#include "log_module.h"
#include "rules_module.h"

/* Define Section */
#define NETWORK_DEVICE_IN_NAME								"eth1"
#define NETWORK_DEVICE_OUT_NAME								"eth2"

#define DEFAULT_PACKET_ACTION_POLICY						NF_DROP

/* Messages Section */
#define REGISTER_HOOKES_BEGIN								"Register hooks begin!\n"
#define REGISTER_HOOKES_ENDED								"Register hooks end!\n"

#define UNREGISTER_HOOKES_BEGIN								"Unregister hooks begin!\n"
#define UNREGISTER_HOOKES_ENDED								"Unregister hooks end!\n"

#define PACKET_HANDLER_FRMT									" Packet handler=%u\n"
#define PACKET_VERDICT_FRMT									" Packet verdict is %u because %d\n"

#define PACKET_INFO_FETCHED_FRMT							" Packet protocol=%hhu [%u -> %u]"
#define PACKET_INFO_FETCHED_SUCCESSFULLY					" Packet info fetched successfully!\n"
#define PACKET_INFO_FETCHED_UNRECOGNIZE						" Packet info fetched unrecognized!\n"

/* Enum Section */
enum FirewallHooksIndexs
{		
	HOOK_IPV4_WITH_OTHERS_INDEX,
	HOOKS_NUMBER,
};

/* Struct Section */
typedef struct fw_hook {
	struct nf_hook_ops* pnfho;
	int pf;
	int hooknum;
	nf_hookfn* handler;
} fw_hook;

/* Methods Section */
EDevReturnValue registerHooks(void);
void 			unregisterHooks(void);

#endif