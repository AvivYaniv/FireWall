#ifndef _PACKET_VERDICT_H_
#define _PACKET_VERDICT_H_

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

/* Define Section */
#define DEFAULT_VERDICT				(-1)

/* Enum Section */
typedef enum {
	VERDICT_NONE      			 =  DEFAULT_VERDICT,
	VERDICT_ALLOW				 =  NF_ACCEPT,
	VERDICT_BLOCK           	 =  NF_DROP,
} verdict_t;

#endif
