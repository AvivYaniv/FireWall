#ifndef _FIREWALL_MODULE_H_
#define _FIREWALL_MODULE_H_

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/time.h>

#include "fw.h"
#include "log_module.h"
#include "rules_module.h"

#include "connection_table.h"

#ifdef PRINT_DEBUG_MESSAGES
#include "tcp_connection.h"
#endif

#ifdef DEBUG
	/* #define DEBUG_HOOK_POST_ROUTING */
	/* #define DEBUG_PASS_NO_PRINT_LOCALHOST */
#endif

/* Define Section */
#define HOST1_IP											0x0101010A /* 10.1.1.1 */
#define HOST2_IP											0x0202010A /* 10.1.2.2 */

#define NETWORK_DEVICE_IN_NAME								"eth1"
#define NETWORK_DEVICE_OUT_NAME								"eth2"

#define DEFAULT_PACKET_ACTION_POLICY						NF_DROP

/* Messages Section */
#define REGISTER_HOOKES_BEGIN								"Register hooks begin!\n"
#define REGISTER_HOOKES_ENDED								"Register hooks end!\n"

#define UNREGISTER_HOOKES_BEGIN								"Unregister hooks begin!\n"
#define UNREGISTER_HOOKES_ENDED								"Unregister hooks end!\n"

#define INIT_FIREWALL_BEGIN									"Init firewall begin!\n"
#define INIT_FIREWALL_ENDED									"Init firewall end!\n"

#define PACKET_INCOMING_HDR									"*** Packet IN coming! ***"
#define PACKET_OUTGOING_HDR									"*** Packet OUT going! ***"
#define PACKET_POST_HDR										"*** Packet POST going! ***"

#define PACKET_HANDLER_FRMT									" Packet handler=%u\n"
#define PACKET_VERDICT_FRMT									" Packet verdict is %u because %d\n"

#define PACKET_INFO_FRMT									" Packet protocol=%hhu [%X %hu -> %X %hu]"
#define PACKET_INFO_FETCHED_SUCCESSFULLY					" Packet info fetched successfully!\n"
#define PACKET_INFO_FETCHED_UNRECOGNIZE						" Packet info fetched unrecognized!\n"

#define FIREWALL_IN_PACKET_DETAILS_FRMT						" Firewall In: Packet protocol=%hhu [%X %d -> %X %d] \n"
#define FIREWALL_OUT_PACKET_DETAILS_FRMT					" Firewall Out: Packet protocol=%hhu [%X %d-> %X %d] \n"

#define PACKET_TO_STATEFUL_FIREWALL_INSPECTION				" Packet [%X %d] \n"
#define PACKET_FROM_STATEFUL_FIREWALL_INSPECTION			" Packet [%X %d] from stateful firewall inspection\n"

#define PACKET_MANIPULATION_TO_FIREWALL_FAILED_FRMT			" Packet manipulation to firewall failed: %s \n"
#define PACKET_DIRECTION_ILLEGAL							"Packet direction illegal"

/* Enum Section */
enum FirewallHooksIndexs
{		
	HOOK_IPV4_PRE_ROUTING_INDEX,
	HOOK_IPV4_LOCAL_OUT_INDEX,

	#ifdef DEBUG_HOOK_POST_ROUTING
		HOOK_WITH_OTHERS_DEBUG,
	#endif

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