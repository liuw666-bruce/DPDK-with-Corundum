/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2020 Intel Corporation
 */

#ifndef _MQNIC_DEFINES_H_
#define _MQNIC_DEFINES_H_

/* 802.1q VLAN Packet Size */
#define VLAN_TAG_SIZE			4    /* 802.3ac tag (not DMA'd) */
#define MQNIC_VLAN_FILTER_TBL_SIZE	128  /* VLAN Filter Table (4096 bits) */

/* Receive Address
 * Number of high/low register pairs in the RAR. The RAR (Receive Address
 * Registers) holds the directed and multicast addresses that we monitor.
 * Technically, we have 16 spots.  However, we reserve one of these spots
 * (RAR[15]) for our directed address used by controllers with
 * manageability enabled, allowing us room for 15 multicast addresses.
 */
#define MQNIC_RAR_ENTRIES	15
#define MQNIC_RAH_AV		0x80000000 /* Receive descriptor valid */
#define MQNIC_RAL_MAC_ADDR_LEN	4
#define MQNIC_RAH_MAC_ADDR_LEN	2
#define MQNIC_RAH_QUEUE_MASK_82575	0x000C0000
#define MQNIC_RAH_POOL_1	0x00040000


/* Error Codes */
#define MQNIC_SUCCESS			0
#define MQNIC_ERR_NVM			1
#define MQNIC_ERR_PHY			2
#define MQNIC_ERR_CONFIG		3
#define MQNIC_ERR_PARAM			4
#define MQNIC_ERR_MAC_INIT		5
#define MQNIC_ERR_PHY_TYPE		6
#define MQNIC_ERR_RESET			9
#define MQNIC_ERR_MASTER_REQUESTS_PENDING	10
#define MQNIC_ERR_HOST_INTERFACE_COMMAND	11
#define MQNIC_BLK_PHY_RESET		12
#define MQNIC_ERR_SWFW_SYNC		13
#define MQNIC_NOT_IMPLEMENTED		14
#define MQNIC_ERR_MBX			15
#define MQNIC_ERR_INVALID_ARGUMENT	16
#define MQNIC_ERR_NO_SPACE		17
#define MQNIC_ERR_NVM_PBA_SECTION	18
#define MQNIC_ERR_I2C			19
#define MQNIC_ERR_INVM_VALUE_NOT_FOUND	20


#ifndef ETH_ALEN
#define ETH_ALEN 6
#endif

#define ETH_HLEN 14

#ifndef ilog2
static inline int rss_ilog2(uint32_t x)
{
	int log = 0;
	x >>= 1;

	while (x) {
		log++;
		x >>= 1;
	}
	return log;
}
#define ilog2(x) rss_ilog2(x)

static inline uint32_t fls(uint32_t x)
{
	uint32_t position;
	uint32_t i;

	if (x == 0)
		return 0;

	for (i = (x >> 1), position = 0; i != 0; ++position)
		i >>= 1;

	return position + 1;
}

static inline uint32_t roundup_pow_of_two(uint32_t x)
{
	return 1UL << fls(x - 1);
}

#endif

#endif /* _MQNIC_DEFINES_H_ */
