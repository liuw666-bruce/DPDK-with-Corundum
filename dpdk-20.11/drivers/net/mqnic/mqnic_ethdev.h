/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2015 Intel Corporation
 */

#ifndef _MQNIC_ETHDEV_H_
#define _MQNIC_ETHDEV_H_

#include <stdint.h>

#include <rte_flow.h>
#include <rte_time.h>
#include <rte_pci.h>

#define MQNIC_INTEL_VENDOR_ID 0x1234


/* need update link, bit flag */
#define MQNIC_FLAG_NEED_LINK_UPDATE (uint32_t)(1 << 0)
#define MQNIC_FLAG_MAILBOX          (uint32_t)(1 << 1)

/*
 * Defines that were not part of mqnic_hw.h as they are not used by the FreeBSD
 * driver.
 */
#define MQNIC_ADVTXD_POPTS_TXSM     0x00000200 /* L4 Checksum offload request */
#define MQNIC_ADVTXD_POPTS_IXSM     0x00000100 /* IP Checksum offload request */
#define MQNIC_ADVTXD_TUCMD_L4T_RSV  0x00001800 /* L4 Packet TYPE of Reserved */
#define MQNIC_RXD_STAT_TMST         0x10000    /* Timestamped Packet indication */
#define MQNIC_RXD_ERR_CKSUM_BIT     29
#define MQNIC_RXD_ERR_CKSUM_MSK     3
#define MQNIC_ADVTXD_MACLEN_SHIFT   9          /* Bit shift for l2_len */
#define MQNIC_CTRL_EXT_EXTEND_VLAN  (1<<26)    /* EXTENDED VLAN */
#define IGB_VFTA_SIZE 128

#define IGB_HKEY_MAX_INDEX             10
#define IGB_MAX_RX_QUEUE_NUM           8
#define IGB_MAX_RX_QUEUE_NUM_82576     16

#define MQNIC_I219_MAX_RX_QUEUE_NUM		2
#define MQNIC_I219_MAX_TX_QUEUE_NUM		2

#define MQNIC_SYN_FILTER_ENABLE        0x00000001 /* syn filter enable field */
#define MQNIC_SYN_FILTER_QUEUE         0x0000000E /* syn filter queue field */
#define MQNIC_SYN_FILTER_QUEUE_SHIFT   1          /* syn filter queue field */
#define MQNIC_RFCTL_SYNQFP             0x00080000 /* SYNQFP in RFCTL register */

#define MQNIC_ETQF_ETHERTYPE           0x0000FFFF
#define MQNIC_ETQF_QUEUE               0x00070000
#define MQNIC_ETQF_QUEUE_SHIFT         16
#define MQNIC_MAX_ETQF_FILTERS         8

#define MQNIC_IMIR_DSTPORT             0x0000FFFF
#define MQNIC_IMIR_PRIORITY            0xE0000000
#define MQNIC_MAX_TTQF_FILTERS         8
#define MQNIC_2TUPLE_MAX_PRI           7

#define MQNIC_MAX_FLEX_FILTERS           8
#define MQNIC_MAX_FHFT                   4
#define MQNIC_MAX_FHFT_EXT               4
#define MQNIC_FHFT_SIZE_IN_DWD           64
#define MQNIC_MAX_FLEX_FILTER_PRI        7
#define MQNIC_MAX_FLEX_FILTER_LEN        128
#define MQNIC_MAX_FLEX_FILTER_DWDS \
	(MQNIC_MAX_FLEX_FILTER_LEN / sizeof(uint32_t))
#define MQNIC_FLEX_FILTERS_MASK_SIZE \
	(MQNIC_MAX_FLEX_FILTER_DWDS / 2)
#define MQNIC_FHFT_QUEUEING_LEN          0x0000007F
#define MQNIC_FHFT_QUEUEING_QUEUE        0x00000700
#define MQNIC_FHFT_QUEUEING_PRIO         0x00070000
#define MQNIC_FHFT_QUEUEING_OFFSET       0xFC
#define MQNIC_FHFT_QUEUEING_QUEUE_SHIFT  8
#define MQNIC_FHFT_QUEUEING_PRIO_SHIFT   16
#define MQNIC_WUFC_FLEX_HQ               0x00004000

#define MQNIC_SPQF_SRCPORT               0x0000FFFF

#define MQNIC_MAX_FTQF_FILTERS           8
#define MQNIC_FTQF_PROTOCOL_MASK         0x000000FF
#define MQNIC_FTQF_5TUPLE_MASK_SHIFT     28
#define MQNIC_FTQF_QUEUE_MASK            0x03ff0000
#define MQNIC_FTQF_QUEUE_SHIFT           16
#define MQNIC_FTQF_QUEUE_ENABLE          0x00000100

#define IGB_RSS_OFFLOAD_ALL ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_IPV6_EX | \
	ETH_RSS_IPV6_TCP_EX | \
	ETH_RSS_IPV6_UDP_EX)

/*
 * The overhead from MTU to max frame size.
 * Considering VLAN so a tag needs to be counted.
 */
#define MQNIC_ETH_OVERHEAD (RTE_ETHER_HDR_LEN + RTE_ETHER_CRC_LEN + \
				VLAN_TAG_SIZE)

/*
 * Maximum number of Ring Descriptors.
 *
 * Since RDLEN/TDLEN should be multiple of 128 bytes, the number of ring
 * desscriptors should meet the following condition:
 * (num_ring_desc * sizeof(struct mqnic_rx/tx_desc)) % 128 == 0
 */
#define	MQNIC_MIN_RING_DESC	32
#define	MQNIC_MAX_RING_DESC	1024

/*
 * TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary.
 * This will also optimize cache line size effect.
 * H/W supports up to cache line size 128.
 */
#define	MQNIC_ALIGN	128

//#define	IGB_RXD_ALIGN	(MQNIC_ALIGN / sizeof(union mqnic_adv_rx_desc))
//#define	IGB_TXD_ALIGN	(MQNIC_ALIGN / sizeof(union mqnic_adv_tx_desc))

#define	IGB_RXD_ALIGN	(MQNIC_ALIGN / MQNIC_DESC_SIZE)
#define	IGB_TXD_ALIGN	(MQNIC_ALIGN / MQNIC_DESC_SIZE)

#define	EM_RXD_ALIGN	(MQNIC_ALIGN / sizeof(struct mqnic_rx_desc))
#define	EM_TXD_ALIGN	(MQNIC_ALIGN / sizeof(struct mqnic_data_desc))

#define MQNIC_MISC_VEC_ID               RTE_INTR_VEC_ZERO_OFFSET
#define MQNIC_RX_VEC_START              RTE_INTR_VEC_RXTX_OFFSET

#define IGB_TX_MAX_SEG     UINT8_MAX
#define IGB_TX_MAX_MTU_SEG UINT8_MAX
#define EM_TX_MAX_SEG      UINT8_MAX
#define EM_TX_MAX_MTU_SEG  UINT8_MAX

#define MAC_TYPE_FILTER_SUP(type)    do {\
	if ((type) != mqnic_82580 && (type) != mqnic_i350 &&\
		(type) != mqnic_82576 && (type) != mqnic_i210 &&\
		(type) != mqnic_i211)\
		return -ENOTSUP;\
} while (0)

#define MAC_TYPE_FILTER_SUP_EXT(type)    do {\
	if ((type) != mqnic_82580 && (type) != mqnic_i350 &&\
		(type) != mqnic_i210 && (type) != mqnic_i211)\
		return -ENOTSUP; \
} while (0)

/* structure for interrupt relative data */
struct mqnic_interrupt {
	uint32_t flags;
	uint32_t mask;
};

struct mqnic_ring {
    // written on enqueue (i.e. start_xmit)
    uint32_t head_ptr;
    uint64_t bytes;
    uint64_t packets;
    uint64_t dropped_packets;
    struct netdev_queue *tx_queue;

    // written from completion
    uint32_t tail_ptr;
    uint32_t clean_tail_ptr;
    uint64_t ts_s;
    u8 ts_valid;

    // mostly constant
    uint32_t size;  //number of desc
    uint32_t full_size;
    uint32_t size_mask;
    uint32_t stride;

    uint32_t cpl_index;

    uint32_t mtu;
    uint32_t page_order;

    uint32_t desc_block_size;
    uint32_t log_desc_block_size;

    size_t buf_size;
    u8 *buf;
    uint64_t buf_dma_addr;

    //union {
   //     struct mqnic_tx_info *tx_info;
   //     struct mqnic_rx_info *rx_info;
    //};

    uint32_t hw_ptr_mask;
    u8 *hw_addr;
    u8 *hw_head_ptr;
    u8 *hw_tail_ptr;
} ____cacheline_aligned_in_smp;

struct mqnic_cq_ring {
    uint32_t head_ptr;

    uint32_t tail_ptr;

    uint32_t size;
    uint32_t size_mask;
    uint32_t stride;

    size_t buf_size;
    u8 *buf;
    uint64_t buf_dma_addr;

    //struct net_device *ndev;
   // struct napi_struct napi;
    int ring_index;
    int eq_index;

    void (*handler) (struct mqnic_cq_ring *);

    uint32_t hw_ptr_mask;
    u8 *hw_addr;
    u8 *hw_head_ptr;
    u8 *hw_tail_ptr;
};

struct mqnic_eq_ring {
    uint32_t head_ptr;

    uint32_t tail_ptr;

    uint32_t size;
    uint32_t size_mask;
    uint32_t stride;

    size_t buf_size;
    u8 *buf;
    uint64_t buf_dma_addr;

    //struct net_device *ndev;
    int int_index;

    int irq;

    void (*handler) (struct mqnic_eq_ring *);

    uint32_t hw_ptr_mask;
    u8 *hw_addr;
    u8 *hw_head_ptr;
    u8 *hw_tail_ptr;
};

struct mqnic_port {
    struct device *dev;
    struct net_device *ndev;

    int index;

    uint32_t tx_queue_count;

    uint32_t port_id;
    uint32_t port_features;
    uint32_t port_mtu;
    uint32_t sched_count;
    uint32_t sched_offset;
    uint32_t sched_stride;
    uint32_t sched_type;

    u8 *hw_addr;
};

struct mqnic_priv {
    //spinlock_t stats_lock;

    bool registered;
    int port;
    bool port_up;

    uint32_t if_id;
    uint32_t if_features;
    uint32_t event_queue_count;
    uint32_t event_queue_offset;
    uint32_t tx_queue_count;
    uint32_t tx_queue_offset;
    uint32_t tx_cpl_queue_count;
    uint32_t tx_cpl_queue_offset;
    uint32_t rx_queue_count;
    uint32_t rx_queue_offset;
    uint32_t rx_cpl_queue_count;
    uint32_t rx_cpl_queue_offset;
    uint32_t port_count;
    uint32_t port_offset;
    uint32_t port_stride;

	uint32_t desc_block_size;
    uint32_t max_desc_block_size;

	uint64_t ipackets;  /**< Total number of successfully received packets. */
	uint64_t opackets;  /**< Total number of successfully transmitted packets.*/
	uint64_t ibytes;    /**< Total number of successfully received bytes. */
	uint64_t obytes;    /**< Total number of successfully transmitted bytes. */

    u8 *hw_addr;
    u8 *csr_hw_addr;

    struct mqnic_eq_ring *event_ring[MQNIC_MAX_EVENT_RINGS];
    struct mqnic_ring *tx_ring[MQNIC_MAX_TX_RINGS];
    struct mqnic_cq_ring *tx_cpl_ring[MQNIC_MAX_TX_CPL_RINGS];
    struct mqnic_ring *rx_ring[MQNIC_MAX_RX_RINGS];
    struct mqnic_cq_ring *rx_cpl_ring[MQNIC_MAX_RX_CPL_RINGS];
    struct mqnic_port *ports[MQNIC_MAX_PORTS];
};

/*
 * Structure to store private data for each driver instance (for each port).
 */
struct mqnic_adapter {
	struct mqnic_hw         hw;
	struct mqnic_priv priv;
	//struct mqnic_hw_stats   stats;
	//struct mqnic_interrupt  intr;
	//struct mqnic_filter_info filter;
	bool stopped;
	//struct rte_timecounter  systime_tc;
	//struct rte_timecounter  rx_tstamp_tc;
	//struct rte_timecounter  tx_tstamp_tc;
};

#define MQNIC_DEV_PRIVATE(adapter) \
	((struct mqnic_adapter *)adapter)

#define MQNIC_DEV_PRIVATE_TO_HW(adapter) \
	(&((struct mqnic_adapter *)adapter)->hw)

#define MQNIC_DEV_PRIVATE_TO_PRIV(adapter) \
	(&((struct mqnic_adapter *)adapter)->priv)

#define MQNIC_DEV_PRIVATE_TO_STATS(adapter) \
	(&((struct mqnic_adapter *)adapter)->stats)

#define MQNIC_DEV_PRIVATE_TO_INTR(adapter) \
	(&((struct mqnic_adapter *)adapter)->intr)

#define MQNIC_DEV_PRIVATE_TO_VFTA(adapter) \
	(&((struct mqnic_adapter *)adapter)->shadow_vfta)

#define MQNIC_DEV_PRIVATE_TO_P_VFDATA(adapter) \
        (&((struct mqnic_adapter *)adapter)->vfdata)

#define MQNIC_DEV_PRIVATE_TO_FILTER_INFO(adapter) \
	(&((struct mqnic_adapter *)adapter)->filter)


/*
 * RX/TX IGB function prototypes
 */
void eth_mqnic_tx_queue_release(void *txq);
void eth_mqnic_rx_queue_release(void *rxq);
void mqnic_dev_clear_queues(struct rte_eth_dev *dev);
void mqnic_dev_free_queues(struct rte_eth_dev *dev);
void mqnic_dev_deactive_queues(struct rte_eth_dev *dev);

uint64_t mqnic_get_rx_port_offloads_capa(struct rte_eth_dev *dev);
uint64_t mqnic_get_rx_queue_offloads_capa(struct rte_eth_dev *dev);

int eth_mqnic_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool);

uint32_t eth_mqnic_rx_queue_count(struct rte_eth_dev *dev,
		uint16_t rx_queue_id);

int eth_mqnic_rx_descriptor_done(void *rx_queue, uint16_t offset);

int eth_mqnic_rx_descriptor_status(void *rx_queue, uint16_t offset);
int eth_mqnic_tx_descriptor_status(void *tx_queue, uint16_t offset);

uint64_t mqnic_get_tx_port_offloads_capa(struct rte_eth_dev *dev);
uint64_t mqnic_get_tx_queue_offloads_capa(struct rte_eth_dev *dev);

int eth_mqnic_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf);

int eth_mqnic_tx_done_cleanup(void *txq, uint32_t free_cnt);

int eth_mqnic_rx_init(struct rte_eth_dev *dev);

void eth_mqnic_tx_init(struct rte_eth_dev *dev);

uint16_t eth_mqnic_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);

//uint16_t eth_mqnic_prep_pkts(void *txq, struct rte_mbuf **tx_pkts,
//		uint16_t nb_pkts);

uint16_t eth_mqnic_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);

uint16_t eth_mqnic_recv_scattered_pkts(void *rxq,
		struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

int eth_mqnic_rss_hash_update(struct rte_eth_dev *dev,
			    struct rte_eth_rss_conf *rss_conf);

int eth_mqnic_rss_hash_conf_get(struct rte_eth_dev *dev,
			      struct rte_eth_rss_conf *rss_conf);

int eth_mqnicvf_rx_init(struct rte_eth_dev *dev);

void eth_mqnicvf_tx_init(struct rte_eth_dev *dev);

/*
 * misc function prototypes
 */
void mqnic_pf_host_init(struct rte_eth_dev *eth_dev);

void mqnic_pf_mbx_process(struct rte_eth_dev *eth_dev);

int mqnic_pf_host_configure(struct rte_eth_dev *eth_dev);

void mqnic_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_rxq_info *qinfo);

void mqnic_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_txq_info *qinfo);

uint32_t em_get_max_pktlen(struct rte_eth_dev *dev);

/*
 * RX/TX EM function prototypes
 */
void eth_em_tx_queue_release(void *txq);
void eth_em_rx_queue_release(void *rxq);

void em_dev_clear_queues(struct rte_eth_dev *dev);
void em_dev_free_queues(struct rte_eth_dev *dev);

uint64_t em_get_rx_port_offloads_capa(struct rte_eth_dev *dev);
uint64_t em_get_rx_queue_offloads_capa(struct rte_eth_dev *dev);

int eth_em_rx_queue_setup(struct rte_eth_dev *dev, uint16_t rx_queue_id,
		uint16_t nb_rx_desc, unsigned int socket_id,
		const struct rte_eth_rxconf *rx_conf,
		struct rte_mempool *mb_pool);

uint32_t eth_em_rx_queue_count(struct rte_eth_dev *dev,
		uint16_t rx_queue_id);

int eth_em_rx_descriptor_done(void *rx_queue, uint16_t offset);

int eth_em_rx_descriptor_status(void *rx_queue, uint16_t offset);
int eth_em_tx_descriptor_status(void *tx_queue, uint16_t offset);

uint64_t em_get_tx_port_offloads_capa(struct rte_eth_dev *dev);
uint64_t em_get_tx_queue_offloads_capa(struct rte_eth_dev *dev);

int eth_em_tx_queue_setup(struct rte_eth_dev *dev, uint16_t tx_queue_id,
		uint16_t nb_tx_desc, unsigned int socket_id,
		const struct rte_eth_txconf *tx_conf);

int eth_em_rx_init(struct rte_eth_dev *dev);

void eth_em_tx_init(struct rte_eth_dev *dev);

uint16_t eth_em_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);

uint16_t eth_em_prep_pkts(void *txq, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts);

uint16_t eth_em_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);

uint16_t eth_em_recv_scattered_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);

void em_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_rxq_info *qinfo);

void em_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_txq_info *qinfo);

void mqnic_pf_host_uninit(struct rte_eth_dev *dev);

void mqnic_filterlist_flush(struct rte_eth_dev *dev);

struct mqnic_frag {
    uint64_t dma_addr;
    uint32_t len;
};

void mqnic_arm_cq(struct mqnic_cq_ring *ring);
void mqnic_cpl_queue_release(struct mqnic_cq_ring *ring);


#endif /* _MQNIC_ETHDEV_H_ */
