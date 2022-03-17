/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */

#include <sys/queue.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>
#include <inttypes.h>

#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_prefetch.h>
#include <rte_udp.h>
#include <rte_tcp.h>
#include <rte_sctp.h>
#include <rte_net.h>
#include <rte_string_fns.h>

#include "mqnic_logs.h"
#include "mqnic_hw.h"
#include "mqnic_ethdev.h"

#if 0
#ifdef RTE_LIBRTE_IEEE1588
#define IGB_TX_IEEE1588_TMST PKT_TX_IEEE1588_TMST
#else
#define IGB_TX_IEEE1588_TMST 0
#endif
/* Bit Mask to indicate what bits required for building TX context */
#define IGB_TX_OFFLOAD_MASK (			 \
		PKT_TX_OUTER_IPV6 |	 \
		PKT_TX_OUTER_IPV4 |	 \
		PKT_TX_IPV6 |		 \
		PKT_TX_IPV4 |		 \
		PKT_TX_VLAN_PKT |		 \
		PKT_TX_IP_CKSUM |		 \
		PKT_TX_L4_MASK |		 \
		PKT_TX_TCP_SEG |		 \
		IGB_TX_IEEE1588_TMST)

#define IGB_TX_OFFLOAD_NOTSUP_MASK \
		(PKT_TX_OFFLOAD_MASK ^ IGB_TX_OFFLOAD_MASK)
#endif

/**
 * Structure associated with each descriptor of the RX ring of a RX queue.
 */
struct mqnic_rx_entry {
	struct rte_mbuf *mbuf; /**< mbuf associated with RX descriptor. */
};

/**
 * Structure associated with each descriptor of the TX ring of a TX queue.
 */
struct mqnic_tx_entry {
	struct rte_mbuf *mbuf; /**< mbuf associated with TX desc, if any. */
	uint16_t next_id; /**< Index of next descriptor in ring. */
	uint16_t last_id; /**< Index of last scattered descriptor. */
};

/**
 * rx queue flags
 */
enum mqnic_rxq_flags {
	IGB_RXQ_FLAG_LB_BSWAP_VLAN = 0x01,
};

/**
 * Structure associated with each RX queue.
 */
struct mqnic_rx_queue {
	struct rte_mempool  *mb_pool;   /**< mbuf pool to populate RX ring. */
	//volatile union mqnic_adv_rx_desc *rx_ring; /**< RX ring virtual address. */
	volatile struct mqnic_desc *rx_ring; /**< RX ring virtual address. */
	uint64_t            rx_ring_phys_addr; /**< RX ring DMA address. */
	volatile uint32_t   *rdt_reg_addr; /**< RDT register address. */
	volatile uint32_t   *rdh_reg_addr; /**< RDH register address. */
	struct mqnic_rx_entry *sw_ring;   /**< address of RX software ring. */
	struct rte_mbuf *pkt_first_seg; /**< First segment of current packet. */
	struct rte_mbuf *pkt_last_seg;  /**< Last segment of current packet. */
	uint16_t            nb_rx_desc; /**< number of RX descriptors. */
	uint16_t            rx_tail;    /**< current value of RDT register. */
	uint16_t            nb_rx_hold; /**< number of held free RX desc. */
	uint16_t            rx_free_thresh; /**< max free RX desc to hold. */
	uint16_t            queue_id;   /**< RX queue index. */
	uint16_t            reg_idx;    /**< RX queue register index. */
	uint16_t            port_id;    /**< Device port identifier. */
	uint8_t             pthresh;    /**< Prefetch threshold register. */
	uint8_t             hthresh;    /**< Host threshold register. */
	uint8_t             wthresh;    /**< Write-back threshold register. */
	uint8_t             crc_len;    /**< 0 if CRC stripped, 4 otherwise. */
	uint8_t             drop_en;  /**< If not 0, set SRRCTL.Drop_En. */
	uint32_t            flags;      /**< RX flags. */
	uint64_t	    offloads;   /**< offloads of DEV_RX_OFFLOAD_* */

	// corundum
	// written on enqueue (i.e. start_xmit)
    u32 head_ptr;
    u64 bytes;
    u64 packets;
    u64 dropped_packets;
    //struct netdev_queue *tx_queue;

    // written from completion
    u32 tail_ptr;
    u32 clean_tail_ptr;
    u64 ts_s;
    u8 ts_valid;

    // mostly constant
    u32 size;
    u32 full_size;
    u32 size_mask;
    u32 stride;

    u32 cpl_index;

    u32 mtu;
    u32 page_order;

    u32 desc_block_size;
    u32 log_desc_block_size;

    size_t buf_size;
    u8 *buf;
    uint64_t buf_dma_addr;

    union {
        struct mqnic_tx_info *tx_info;
        struct mqnic_rx_info *rx_info;
    };

    u32 hw_ptr_mask;
    u8 *hw_addr;
    u8 *hw_head_ptr;
    u8 *hw_tail_ptr;

	struct mqnic_priv *priv;
};

/**
 * Hardware context number
 */
enum mqnic_advctx_num {
	IGB_CTX_0    = 0, /**< CTX0    */
	IGB_CTX_1    = 1, /**< CTX1    */
	IGB_CTX_NUM  = 2, /**< CTX_NUM */
};

/** Offload features */
union mqnic_tx_offload {
	uint64_t data;
	struct {
		uint64_t l3_len:9; /**< L3 (IP) Header Length. */
		uint64_t l2_len:7; /**< L2 (MAC) Header Length. */
		uint64_t vlan_tci:16;  /**< VLAN Tag Control Identifier(CPU order). */
		uint64_t l4_len:8; /**< L4 (TCP/UDP) Header Length. */
		uint64_t tso_segsz:16; /**< TCP TSO segment size. */

		/* uint64_t unused:8; */
	};
};

/*
 * Compare mask for mqnic_tx_offload.data,
 * should be in sync with mqnic_tx_offload layout.
 * */
#define TX_MACIP_LEN_CMP_MASK	0x000000000000FFFFULL /**< L2L3 header mask. */
#define TX_VLAN_CMP_MASK		0x00000000FFFF0000ULL /**< Vlan mask. */
#define TX_TCP_LEN_CMP_MASK		0x000000FF00000000ULL /**< TCP header mask. */
#define TX_TSO_MSS_CMP_MASK		0x00FFFF0000000000ULL /**< TSO segsz mask. */
/** Mac + IP + TCP + Mss mask. */
#define TX_TSO_CMP_MASK	\
	(TX_MACIP_LEN_CMP_MASK | TX_TCP_LEN_CMP_MASK | TX_TSO_MSS_CMP_MASK)

/**
 * Strucutre to check if new context need be built
 */
struct mqnic_advctx_info {
	uint64_t flags;           /**< ol_flags related to context build. */
	/** tx offload: vlan, tso, l2-l3-l4 lengths. */
	union mqnic_tx_offload tx_offload;
	/** compare mask for tx offload. */
	union mqnic_tx_offload tx_offload_mask;
};

/**
 * Structure associated with each TX queue.
 */
struct mqnic_tx_queue {
	//volatile union mqnic_adv_tx_desc *tx_ring; /**< TX ring address */
	volatile struct mqnic_desc *tx_ring; /**< TX ring address */
	uint64_t               tx_ring_phys_addr; /**< TX ring DMA address. */
	struct mqnic_tx_entry    *sw_ring; /**< virtual address of SW ring. */
	volatile uint32_t      *tdt_reg_addr; /**< Address of TDT register. */
	uint32_t               txd_type;      /**< Device-specific TXD type */
	uint16_t               nb_tx_desc;    /**< number of TX descriptors. */
	uint16_t               tx_tail; /**< Current value of TDT register. */
	uint16_t               tx_head;
	/**< Index of first used TX descriptor. */
	uint16_t               queue_id; /**< TX queue index. */
	uint16_t               reg_idx;  /**< TX queue register index. */
	uint16_t               port_id;  /**< Device port identifier. */
	uint8_t                pthresh;  /**< Prefetch threshold register. */
	uint8_t                hthresh;  /**< Host threshold register. */
	uint8_t                wthresh;  /**< Write-back threshold register. */
	uint32_t               ctx_curr;
	/**< Current used hardware descriptor. */
	uint32_t               ctx_start;
	/**< Start context position for transmit queue. */
	struct mqnic_advctx_info ctx_cache[IGB_CTX_NUM];
	/**< Hardware context history.*/
	uint64_t	       offloads; /**< offloads of DEV_TX_OFFLOAD_* */

	//mqnic
	// written on enqueue (i.e. start_xmit)
    uint32_t head_ptr;
    uint64_t bytes;
    uint64_t packets;
    uint64_t dropped_packets;
    struct netdev_queue *tx_queue;

    // written from completion
    uint32_t tail_ptr;// ____cacheline_aligned_in_smp;
    uint32_t clean_tail_ptr;
    uint64_t ts_s;
    uint8_t ts_valid;

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
    uint8_t *buf;
    //dma_addr_t buf_dma_addr;

    union {
        struct mqnic_tx_info *tx_info;
        struct mqnic_rx_info *rx_info;
    };

    uint32_t hw_ptr_mask;
    uint8_t *hw_addr;
    uint8_t *hw_head_ptr;
    uint8_t *hw_tail_ptr;

	int done;

	struct mqnic_priv *priv;
};

#if 1
#define RTE_PMD_USE_PREFETCH
#endif

#ifdef RTE_PMD_USE_PREFETCH
#define rte_mqnic_prefetch(p)	rte_prefetch0(p)
#else
#define rte_mqnic_prefetch(p)	do {} while(0)
#endif

#ifdef RTE_PMD_PACKET_PREFETCH
#define rte_packet_prefetch(p) rte_prefetch1(p)
#else
#define rte_packet_prefetch(p)	do {} while(0)
#endif

/*
 * Macro for VMDq feature for 1 GbE NIC.
 */
#define MQNIC_VMOLR_SIZE			(8)
#define IGB_TSO_MAX_HDRLEN			(512)
#define IGB_TSO_MAX_MSS				(9216)

/*********************************************************************
 *
 *  TX function
 *
 **********************************************************************/

static void 
mqnic_deactivate_tx_queue(struct mqnic_tx_queue *txq)
{
    // deactivate queue
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(txq->size) | (txq->log_desc_block_size << 8));
}

static void 
mqnic_deactivate_rx_queue(struct mqnic_rx_queue *rxq)
{
    // deactivate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(rxq->size) | (rxq->log_desc_block_size << 8));
}

static int
mqnic_activate_rxq(struct mqnic_rx_queue *rxq, int cpl_index)
{
	rxq->cpl_index = cpl_index;
	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    // set base address
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+0, rxq->rx_ring_phys_addr);
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+4, rxq->rx_ring_phys_addr >> 32);
    // set completion queue index
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_CPL_QUEUE_INDEX_REG, rxq->cpl_index);
    // set pointers
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_HEAD_PTR_REG, rxq->head_ptr & rxq->hw_ptr_mask);
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_TAIL_PTR_REG, rxq->tail_ptr & rxq->hw_ptr_mask);
    // set size and activate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(rxq->size) | (rxq->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK);
    return 0;
}

static bool 
mqnic_is_tx_queue_full(const struct mqnic_tx_queue *txq)
{
    return txq->head_ptr - txq->clean_tail_ptr >= txq->full_size;
}

static void 
mqnic_tx_read_tail_ptr(struct mqnic_tx_queue *txq)
{
    txq->tail_ptr += (MQNIC_DIRECT_READ_REG(txq->hw_tail_ptr, 0) - txq->tail_ptr) & txq->hw_ptr_mask;
	PMD_TX_LOG(DEBUG, "get txq->tail_ptr = %d", txq->tail_ptr);
}

static void 
mqnic_cq_read_head_ptr(struct mqnic_cq_ring *ring)
{
    ring->head_ptr += (MQNIC_DIRECT_READ_REG(ring->hw_head_ptr, 0) - ring->head_ptr) & ring->hw_ptr_mask;
	PMD_TX_LOG(DEBUG, "get cq ring->head_ptr = %d", ring->head_ptr);
}

static void 
mqnic_rx_cq_write_tail_ptr(struct mqnic_cq_ring *ring)
{
	MQNIC_DIRECT_WRITE_REG(ring->hw_tail_ptr, 0, ring->tail_ptr & ring->hw_ptr_mask);
	PMD_RX_LOG(DEBUG, "update cq ring tail ptr register = %d, ring->tail_ptr = %d", ring->tail_ptr & ring->hw_ptr_mask, ring->tail_ptr);
}

static void 
mqnic_tx_cq_write_tail_ptr(struct mqnic_cq_ring *ring)
{
	MQNIC_DIRECT_WRITE_REG(ring->hw_tail_ptr, 0, ring->tail_ptr & ring->hw_ptr_mask);
	PMD_TX_LOG(DEBUG, "update cq ring tail ptr register = %d, ring->tail_ptr = %d", ring->tail_ptr & ring->hw_ptr_mask, ring->tail_ptr);
}

static void 
mqnic_rx_read_tail_ptr(struct mqnic_rx_queue *rxq)
{
    rxq->tail_ptr += (MQNIC_DIRECT_READ_REG(rxq->hw_tail_ptr, 0) - rxq->tail_ptr) & rxq->hw_ptr_mask;
}

static void 
mqnic_rx_write_head_ptr(struct mqnic_rx_queue *rxq)
{
	MQNIC_DIRECT_WRITE_REG(rxq->hw_head_ptr, 0, rxq->head_ptr & rxq->hw_ptr_mask);
}

static inline void
mqnic_check_tx_cpl(struct mqnic_tx_queue *txq)
{
	struct mqnic_priv *priv = txq->priv;
	struct mqnic_cq_ring *cq_ring;

	PMD_TX_LOG(DEBUG, "mqnic_check_tx_cpl start");

	cq_ring = priv->tx_cpl_ring[txq->queue_id];   //assume queue_id of txq == queue_id of tx_cpl_queue
	mqnic_cq_read_head_ptr(cq_ring);

	cq_ring->tail_ptr = cq_ring->head_ptr;
    mqnic_tx_cq_write_tail_ptr(cq_ring);

    // process ring
    mqnic_tx_read_tail_ptr(txq);
	txq->clean_tail_ptr = txq->tail_ptr;

	mqnic_arm_cq(cq_ring);
	PMD_TX_LOG(DEBUG, "mqnic_check_tx_cpl finish");
}

uint16_t
eth_mqnic_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts,
	       uint16_t nb_pkts)
{
	struct mqnic_tx_queue *txq;
	struct mqnic_tx_entry *sw_ring;
	struct mqnic_tx_entry *txe, *txn;
	volatile struct mqnic_desc *txr;
	volatile struct mqnic_desc *txd;
	struct rte_mbuf     *tx_pkt;
	struct rte_mbuf     *m_seg;
	uint64_t buf_dma_addr;
	uint16_t slen;
	uint16_t tx_end;
	uint16_t tx_id;
	uint16_t tx_last;
	uint16_t nb_tx;
	uint32_t i;
	struct mqnic_priv *priv;
    //int budget;

	txq = tx_queue;
	//budget = txq->nb_tx_desc>>1;
	priv= txq->priv;
	sw_ring = txq->sw_ring;
	txr     = txq->tx_ring;
	tx_id   = txq->tx_tail;
	txe = &sw_ring[tx_id];

	//PMD_TX_LOG(ERR, "done = %d, budget = %d", txq->done, budget);
	//if(txq->done > budget){
	//	txq->done = 0;
		mqnic_check_tx_cpl(txq);
	//}

	for (nb_tx = 0; nb_tx < nb_pkts; nb_tx++) {
		tx_pkt = *tx_pkts++;

		RTE_MBUF_PREFETCH_TO_FREE(txe->mbuf);

		/*
		 * The number of descriptors that must be allocated for a
		 * packet is the number of segments of that packet, plus 1
		 * Context Descriptor for the VLAN Tag Identifier, if any.
		 * Determine the last TX descriptor to allocate in the TX ring
		 * for the packet, starting from the current position (tx_id)
		 * in the ring.
		 */
		tx_last = (uint16_t) (tx_id + tx_pkt->nb_segs - 1);

		if (tx_last >= txq->nb_tx_desc)
			tx_last = (uint16_t) (tx_last - txq->nb_tx_desc);

		/*
		 * Check if there are enough free descriptors in the TX ring
		 * to transmit the next packet.
		 * This operation is based on the two following rules:
		 *
		 *   1- Only check that the last needed TX descriptor can be
		 *      allocated (by construction, if that descriptor is free,
		 *      all intermediate ones are also free).
		 *
		 *      For this purpose, the index of the last TX descriptor
		 *      used for a packet (the "last descriptor" of a packet)
		 *      is recorded in the TX entries (the last one included)
		 *      that are associated with all TX descriptors allocated
		 *      for that packet.
		 *
		 *   2- Avoid to allocate the last free TX descriptor of the
		 *      ring, in order to never set the TDT register with the
		 *      same value stored in parallel by the NIC in the TDH
		 *      register, which makes the TX engine of the NIC enter
		 *      in a deadlock situation.
		 *
		 *      By extension, avoid to allocate a free descriptor that
		 *      belongs to the last set of free descriptors allocated
		 *      to the same packet previously transmitted.
		 */

		/*
		 * The "last descriptor" of the previously sent packet, if any,
		 * which used the last descriptor to allocate.
		 */
		tx_end = sw_ring[tx_last].last_id;

		/*
		 * The next descriptor following that "last descriptor" in the
		 * ring.
		 */
		tx_end = sw_ring[tx_end].next_id;

		/*
		 * The "last descriptor" associated with that next descriptor.
		 */
		tx_end = sw_ring[tx_end].last_id;

		if(mqnic_is_tx_queue_full(txq)){
			PMD_TX_LOG(DEBUG, "mqnic_is_tx_queue_full");
			if (nb_tx == 0)
				return 0;
			goto end_of_tx;
		}

		m_seg = tx_pkt;
		do {
			txn = &sw_ring[txe->next_id];
			//txd = &txr[tx_id];
			txd = &txr[tx_id*4];

			if (txe->mbuf != NULL)
				rte_pktmbuf_free_seg(txe->mbuf);
			txe->mbuf = m_seg;

			/*
			 * Set up transmit descriptor.
			 */
			slen = (uint16_t) m_seg->data_len;
			buf_dma_addr = rte_mbuf_data_iova(m_seg);
			//txd->read.buffer_addr =
			//	rte_cpu_to_le_64(buf_dma_addr);
			txd->addr =
				rte_cpu_to_le_64(buf_dma_addr);
			//txd->read.cmd_type_len =
			//	rte_cpu_to_le_32(cmd_type_len | slen);
			txd->len =
				rte_cpu_to_le_32(slen);

    		for (i = 0; i < txq->desc_block_size-1; i++)
    		{
       			txd[i+1].len = 0;
        		txd[i+1].addr = 0;
    		}

			txq->head_ptr++;
			//done++;
			//txd->read.olinfo_status =
			//	rte_cpu_to_le_32(olinfo_status);
			txe->last_id = tx_last;
			tx_id = txe->next_id;
			txe = txn;
			m_seg = m_seg->next;
			priv->opackets++;
			priv->obytes+=slen;
		} while (m_seg != NULL);

	}
 end_of_tx:
	rte_wmb();

	MQNIC_DIRECT_WRITE_REG(txq->hw_head_ptr, 0, txq->head_ptr & txq->hw_ptr_mask);
	PMD_TX_LOG(DEBUG, "port_id=%u queue_id=%u tx_tail=%u nb_tx=%u txq->head_ptr=%u",
		   (unsigned) txq->port_id, (unsigned) txq->queue_id,
		   (unsigned) tx_id, (unsigned) nb_tx, (unsigned) txq->head_ptr);
	txq->tx_tail = tx_id;
	//txq->done += nb_tx;

	return nb_tx;
}

/*********************************************************************
 *
 *  TX prep functions
 *
 **********************************************************************/
uint16_t
eth_mqnic_prep_pkts(__rte_unused void *tx_queue, struct rte_mbuf **tx_pkts,
		uint16_t nb_pkts)
{
	int i, ret;
	struct rte_mbuf *m;

	for (i = 0; i < nb_pkts; i++) {
		m = tx_pkts[i];

		/* Check some limitations for TSO in hardware */
		if (m->ol_flags & PKT_TX_TCP_SEG){
				PMD_TX_LOG(ERR, "corundum don't support TCP segmentation offload");
				rte_errno = ENOTSUP;
				return i;
		}

		//if (m->ol_flags & IGB_TX_OFFLOAD_NOTSUP_MASK) {
		//	PMD_TX_LOG(ERR, "IGB_TX_OFFLOAD_NOTSUP_MASK");
		//	rte_errno = ENOTSUP;
		//	return i;
		//}

#ifdef RTE_LIBRTE_ETHDEV_DEBUG
		ret = rte_validate_tx_offload(m);
		if (ret != 0) {
			rte_errno = -ret;
			return i;
		}
#endif
		ret = rte_net_intel_cksum_prepare(m);
		if (ret != 0) {
			rte_errno = -ret;
			return i;
		}
	}

	return i;
}

/*********************************************************************
 *
 *  RX functions
 *
 **********************************************************************/
uint16_t
eth_mqnic_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
	       uint16_t nb_pkts)
{
	struct mqnic_rx_queue *rxq;
	volatile struct mqnic_desc *rx_ring;
	volatile struct mqnic_desc *rxdp;
	struct mqnic_rx_entry *sw_ring;
	struct mqnic_rx_entry *rxe;
	struct rte_mbuf *rxm;
	struct rte_mbuf *nmb;
	uint64_t dma_addr;
	uint16_t pkt_len;
	uint16_t rx_id;
	uint16_t nb_rx;
	uint16_t nb_hold;
	uint32_t cq_index;
    uint32_t cq_tail_ptr;
	uint32_t cq_desc_inline_index;
	uint32_t ring_clean_tail_ptr;
	volatile struct mqnic_cpl *cpl;
	struct mqnic_cq_ring *cq_ring;
	struct mqnic_priv *priv;
	int done = 0;
    int budget;

	rxq = rx_queue;
	budget = rxq->full_size;
	priv = rxq->priv;
	cq_ring = priv->rx_cpl_ring[rxq->queue_id];
	mqnic_cq_read_head_ptr(cq_ring);

    cq_tail_ptr = cq_ring->tail_ptr;
    cq_index = cq_tail_ptr & cq_ring->size_mask;

	nb_rx = 0;
	nb_hold = 0;
	rx_id = rxq->rx_tail;
	rx_ring = rxq->rx_ring;
	sw_ring = rxq->sw_ring;

	if(cq_ring->ring_index != rxq->queue_id)
		PMD_RX_LOG(ERR, "wrong cq_ring->ring_index, %d != %d", cq_ring->ring_index, rxq->queue_id);

	while ((nb_rx < nb_pkts) && (cq_ring->head_ptr != cq_tail_ptr) && (done < budget)) {
		cpl = (volatile struct mqnic_cpl *)(cq_ring->buf + cq_index*cq_ring->stride);
		cq_desc_inline_index = cpl->index & rxq->size_mask; //number of desc

		PMD_RX_LOG(DEBUG, "eth_mqnic_recv_pkts, nb_pkts = %d, cq_ring->head_ptr = %d, cq_tail_ptr = %d, budget = %d, cpl->len = %d",
			nb_pkts, cq_ring->head_ptr, cq_tail_ptr, budget, cpl->len);
		if(cq_desc_inline_index != cq_index){
			PMD_RX_LOG(ERR, "wrong cq desc index, %d != %d", cq_desc_inline_index, cq_index);
			break;
		}

		if(rx_id != cq_index){
			PMD_RX_LOG(ERR, "wrong rx_id, %d != %d", rx_id, cq_index);
			break;
		}
		rxdp = &rx_ring[rx_id];

		PMD_RX_LOG(DEBUG, "port_id=%u queue_id=%u rx_id=%u ",
			   (unsigned) rxq->port_id, (unsigned) rxq->queue_id,
			   (unsigned) rx_id);

		nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (nmb == NULL) {
			PMD_RX_LOG(ERR, "RX mbuf alloc failed port_id=%u "
				   "queue_id=%u", (unsigned) rxq->port_id,
				   (unsigned) rxq->queue_id);
			rte_eth_devices[rxq->port_id].data->rx_mbuf_alloc_failed++;
			break;
		}

		nb_hold++;
		rxe = &sw_ring[rx_id];
		rx_id++;
		if (rx_id == rxq->nb_rx_desc)
			rx_id = 0;

		/* Prefetch next mbuf while processing current one. */
		rte_mqnic_prefetch(sw_ring[rx_id].mbuf);

		/*
		 * When next RX descriptor is on a cache-line boundary,
		 * prefetch the next 4 RX descriptors and the next 8 pointers
		 * to mbufs.
		 */
		if ((rx_id & 0x3) == 0) {
			rte_mqnic_prefetch(&rx_ring[rx_id]);
			rte_mqnic_prefetch(&sw_ring[rx_id]);
		}

		rxm = rxe->mbuf;
		rxe->mbuf = nmb;
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb));
		rxdp->len = nmb->buf_len;
		PMD_RX_LOG(DEBUG, "nmb->buf_len=%u ", (unsigned) nmb->buf_len);
		rxdp->addr = dma_addr;

		rxq->head_ptr++;

		/*
		 * Initialize the returned mbuf.
		 * 1) setup generic mbuf fields:
		 *    - number of segments,
		 *    - next segment,
		 *    - packet length,
		 *    - RX port identifier.
		 * 2) integrate hardware offload data, if any:
		 *    - RSS flag & hash,
		 *    - IP checksum flag,
		 *    - VLAN TCI, if any,
		 *    - error flags.
		 */
		pkt_len = (uint16_t)cpl->len;
		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rte_packet_prefetch((char *)rxm->buf_addr + rxm->data_off);
		rxm->nb_segs = 1;
		rxm->next = NULL;
		rxm->pkt_len = pkt_len;
		rxm->data_len = pkt_len;
		rxm->port = rxq->port_id;

		/*
		 * Store the mbuf address into the next entry of the array
		 * of returned packets.
		 */
		rx_pkts[nb_rx++] = rxm;
		done++;
		cq_tail_ptr++;
        cq_index = cq_tail_ptr & cq_ring->size_mask;

		priv->ipackets++;
		priv->ibytes+=pkt_len;
	}
	rxq->rx_tail = rx_id;

	// update CQ tail
    cq_ring->tail_ptr = cq_tail_ptr;
    mqnic_rx_cq_write_tail_ptr(cq_ring);

	mqnic_rx_read_tail_ptr(rxq);

    ring_clean_tail_ptr = rxq->clean_tail_ptr;

    while (ring_clean_tail_ptr != rxq->tail_ptr)
    {
        ring_clean_tail_ptr++;
    }

    // update ring tail
    rxq->clean_tail_ptr = ring_clean_tail_ptr;

	mqnic_rx_write_head_ptr(rxq);
	MQNIC_WRITE_FLUSH(priv);
	mqnic_arm_cq(cq_ring);

	return nb_rx;
}

uint16_t
eth_mqnic_recv_scattered_pkts(void *rx_queue, struct rte_mbuf **rx_pkts,
			 uint16_t nb_pkts)
{
	RTE_SET_USED(rx_queue);
	RTE_SET_USED(rx_pkts);
	RTE_SET_USED(nb_pkts);
	PMD_RX_LOG(ERR, "eth_mqnic_recv_scattered_pkts is not supported");
	return 0;

}

/*
 * Maximum number of Ring Descriptors.
 *
 * Since RDLEN/TDLEN should be multiple of 128bytes, the number of ring
 * desscriptors should meet the following condition:
 *      (num_ring_desc * sizeof(struct mqnic_rx/tx_desc)) % 128 == 0
 */

static void
mqnic_tx_queue_release_mbufs(struct mqnic_tx_queue *txq)
{
	unsigned i;

	if (txq->sw_ring != NULL) {
		for (i = 0; i < txq->nb_tx_desc; i++) {
			if (txq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
mqnic_tx_queue_release(struct mqnic_tx_queue *txq)
{
	if (txq != NULL) {
		mqnic_tx_queue_release_mbufs(txq);
		rte_free(txq->sw_ring);
		rte_free(txq);
	}
}

void
mqnic_cpl_queue_release(struct mqnic_cq_ring *ring)
{
	if (ring != NULL) {
		rte_free(ring);
	}
}

void
eth_mqnic_tx_queue_release(void *txq)
{
	mqnic_tx_queue_release(txq);
}

static int
mqnic_tx_done_cleanup(struct mqnic_tx_queue *txq, uint32_t free_cnt)
{
	struct mqnic_tx_entry *sw_ring;
	uint16_t tx_first; /* First segment analyzed. */
	uint16_t tx_id;    /* Current segment being processed. */
	uint16_t tx_last;  /* Last segment in the current packet. */
	uint16_t tx_next;  /* First segment of the next packet. */
	int count = 0;
	PMD_TX_LOG(DEBUG, "mqnic_tx_done_cleanup");

	if (!txq)
		return -ENODEV;

	sw_ring = txq->sw_ring;

	/* tx_tail is the last sent packet on the sw_ring. Goto the end
	 * of that packet (the last segment in the packet chain) and
	 * then the next segment will be the start of the oldest segment
	 * in the sw_ring. This is the first packet that will be
	 * attempted to be freed.
	 */

	/* Get last segment in most recently added packet. */
	tx_first = sw_ring[txq->tx_tail].last_id;

	/* Get the next segment, which is the oldest segment in ring. */
	tx_first = sw_ring[tx_first].next_id;

	/* Set the current index to the first. */
	tx_id = tx_first;

	/* Loop through each packet. For each packet, verify that an
	 * mbuf exists and that the last segment is free. If so, free
	 * it and move on.
	 */
	mqnic_check_tx_cpl(txq);
	while (1) {
		tx_last = sw_ring[tx_id].last_id;

		if (sw_ring[tx_last].mbuf) {
			//if (txr[tx_last].wb.status &
			//    MQNIC_TXD_STAT_DD) {
			if(1){
				/* Increment the number of packets
				 * freed.
				 */
				count++;

				/* Get the start of the next packet. */
				tx_next = sw_ring[tx_last].next_id;

				/* Loop through all segments in a
				 * packet.
				 */
				do {
					if (sw_ring[tx_id].mbuf) {
						rte_pktmbuf_free_seg(
							sw_ring[tx_id].mbuf);
						sw_ring[tx_id].mbuf = NULL;
						sw_ring[tx_id].last_id = tx_id;
					}

					/* Move to next segemnt. */
					tx_id = sw_ring[tx_id].next_id;

				} while (tx_id != tx_next);

				if (unlikely(count == (int)free_cnt))
					break;
			} else {
				/* mbuf still in use, nothing left to
				 * free.
				 */
				break;
			}
		} else {
			/* There are multiple reasons to be here:
			 * 1) All the packets on the ring have been
			 *    freed - tx_id is equal to tx_first
			 *    and some packets have been freed.
			 *    - Done, exit
			 * 2) Interfaces has not sent a rings worth of
			 *    packets yet, so the segment after tail is
			 *    still empty. Or a previous call to this
			 *    function freed some of the segments but
			 *    not all so there is a hole in the list.
			 *    Hopefully this is a rare case.
			 *    - Walk the list and find the next mbuf. If
			 *      there isn't one, then done.
			 */
			if (likely(tx_id == tx_first && count != 0))
				break;

			/* Walk the list and find the next mbuf, if any. */
			do {
				/* Move to next segemnt. */
				tx_id = sw_ring[tx_id].next_id;

				if (sw_ring[tx_id].mbuf)
					break;

			} while (tx_id != tx_first);

			/* Determine why previous loop bailed. If there
			 * is not an mbuf, done.
			 */
			if (!sw_ring[tx_id].mbuf)
				break;
		}
	}

	return count;
}

int
eth_mqnic_tx_done_cleanup(void *txq, uint32_t free_cnt)
{
	return mqnic_tx_done_cleanup(txq, free_cnt);
}

static void
mqnic_reset_tx_queue_stat(struct mqnic_tx_queue *txq)
{
	txq->tx_head = 0;
	txq->tx_tail = 0;
	txq->ctx_curr = 0;
	txq->head_ptr = 0;
    txq->tail_ptr = 0;
    txq->clean_tail_ptr = 0;
	memset((void*)&txq->ctx_cache, 0,
		IGB_CTX_NUM * sizeof(struct mqnic_advctx_info));
}

static void
mqnic_reset_tx_queue(struct mqnic_tx_queue *txq, struct rte_eth_dev *dev)
{
	static const struct mqnic_desc zeroed_desc = {0, 0, 0, 0};
	struct mqnic_tx_entry *txe = txq->sw_ring;
	uint16_t i, prev;
	RTE_SET_USED(dev);

	/* Zero out HW ring memory */
	for (i = 0; i < txq->nb_tx_desc; i++) {
		txq->tx_ring[i] = zeroed_desc;
	}

	/* Initialize ring entries */
	prev = (uint16_t)(txq->nb_tx_desc - 1);
	for (i = 0; i < txq->nb_tx_desc; i++) {
		txe[i].mbuf = NULL;
		txe[i].last_id = i;
		txe[prev].next_id = i;
		prev = i;
	}

	mqnic_reset_tx_queue_stat(txq);
}

uint64_t
mqnic_get_tx_port_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t tx_offload_capa = 0;

	RTE_SET_USED(dev);
#if 0
	tx_offload_capa = DEV_TX_OFFLOAD_VLAN_INSERT |
			  DEV_TX_OFFLOAD_IPV4_CKSUM  |
			  DEV_TX_OFFLOAD_UDP_CKSUM   |
			  DEV_TX_OFFLOAD_TCP_CKSUM   |
			  DEV_TX_OFFLOAD_SCTP_CKSUM  |
			  DEV_TX_OFFLOAD_TCP_TSO     |
			  DEV_TX_OFFLOAD_MULTI_SEGS;
#endif
	return tx_offload_capa;
}

uint64_t
mqnic_get_tx_queue_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t tx_queue_offload_capa;

	tx_queue_offload_capa = mqnic_get_tx_port_offloads_capa(dev);

	return tx_queue_offload_capa;
}

int
eth_mqnic_tx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_txconf *tx_conf)
{
	const struct rte_memzone *tz;
	struct mqnic_tx_queue *txq;
	uint64_t offloads;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	offloads = tx_conf->offloads | dev->data->dev_conf.txmode.offloads;

	/*
	 * Validate number of transmit descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of MQNIC_ALIGN.
	 */
	if (nb_desc % IGB_TXD_ALIGN != 0 ||
			(nb_desc > MQNIC_MAX_RING_DESC) ||
			(nb_desc < MQNIC_MIN_RING_DESC)) {
			PMD_INIT_LOG(INFO, "nb_desc(%d) must > %d and < %d.",
				nb_desc, MQNIC_MIN_RING_DESC, MQNIC_MAX_RING_DESC);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	if (dev->data->tx_queues[queue_idx] != NULL) {
		mqnic_tx_queue_release(dev->data->tx_queues[queue_idx]);
		dev->data->tx_queues[queue_idx] = NULL;
	}

	/* First allocate the tx queue data structure */
	txq = rte_zmalloc("ethdev TX queue", sizeof(struct mqnic_tx_queue),
							RTE_CACHE_LINE_SIZE);
	if (txq == NULL)
		return -ENOMEM;

	txq->size = roundup_pow_of_two(nb_desc);
    txq->full_size = txq->size >> 1;
    txq->size_mask = txq->size-1;
    txq->stride = roundup_pow_of_two(MQNIC_DESC_SIZE*priv->desc_block_size);

    txq->desc_block_size = txq->stride/MQNIC_DESC_SIZE;
    txq->log_desc_block_size = txq->desc_block_size < 2 ? 0 : ilog2(txq->desc_block_size-1)+1;
    txq->desc_block_size = 1 << txq->log_desc_block_size;

	txq->buf_size = txq->size*txq->stride;

	/*
	 * Allocate TX ring hardware descriptors. A memzone large enough to
	 * handle the maximum ring size is allocated in order to allow for
	 * resizing in later calls to the queue setup function.
	 */
	tz = rte_eth_dma_zone_reserve(dev, "tx_ring", queue_idx, txq->buf_size,
				      MQNIC_ALIGN, socket_id);
	if (tz == NULL) {
		mqnic_tx_queue_release(txq);
		return -ENOMEM;
	}

	txq->nb_tx_desc = txq->size;
	txq->queue_id = queue_idx;
	txq->reg_idx = queue_idx;
	txq->port_id = dev->data->port_id;
	txq->tx_ring_phys_addr = tz->iova;
	txq->tx_ring = (struct mqnic_desc *) tz->addr;

	txq->sw_ring = rte_zmalloc("txq->sw_ring",
				   sizeof(struct mqnic_tx_entry) * txq->nb_tx_desc,
				   RTE_CACHE_LINE_SIZE);
	if (txq->sw_ring == NULL) {
		PMD_INIT_LOG(ERR, "failed to alloc sw_ring");
		mqnic_tx_queue_release(txq);
		return -ENOMEM;
	}
	PMD_INIT_LOG(DEBUG, "tx sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
		     txq->sw_ring, txq->tx_ring, txq->tx_ring_phys_addr);

	txq->hw_addr = priv->hw_addr+priv->tx_queue_offset+queue_idx*MQNIC_QUEUE_STRIDE;
    txq->hw_ptr_mask = 0xffff;
    txq->hw_head_ptr = txq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG;
    txq->hw_tail_ptr = txq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG;

	txq->head_ptr = 0;
    txq->tail_ptr = 0;
    txq->clean_tail_ptr = 0;

	txq->done = 0;

	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    // set base address
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+0, txq->tx_ring_phys_addr);
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+4, txq->tx_ring_phys_addr >> 32);
    // set completion queue index
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_CPL_QUEUE_INDEX_REG, 0);
    // set pointers
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_HEAD_PTR_REG, txq->head_ptr & txq->hw_ptr_mask);
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_TAIL_PTR_REG, txq->tail_ptr & txq->hw_ptr_mask);
    // set size
	MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(txq->size) | (txq->log_desc_block_size << 8));

	mqnic_reset_tx_queue(txq, dev);
	dev->tx_pkt_burst = eth_mqnic_xmit_pkts;
	dev->tx_pkt_prepare = &eth_mqnic_prep_pkts;
	dev->data->tx_queues[queue_idx] = txq;
	txq->offloads = offloads;

	return 0;
}

static void
mqnic_rx_queue_release_mbufs(struct mqnic_rx_queue *rxq)
{
	unsigned i;

	if (rxq->sw_ring != NULL) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf != NULL) {
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
				rxq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
mqnic_rx_queue_release(struct mqnic_rx_queue *rxq)
{
	if (rxq != NULL) {
		mqnic_rx_queue_release_mbufs(rxq);
		rte_free(rxq->sw_ring);
		rte_free(rxq);
	}
}

void
eth_mqnic_rx_queue_release(void *rxq)
{
	mqnic_rx_queue_release(rxq);
}

static void
mqnic_reset_rx_queue(struct mqnic_rx_queue *rxq)
{
	//static const union mqnic_adv_rx_desc zeroed_desc = {{0}};
	static const struct mqnic_desc zeroed_desc = {0, 0, 0, 0};
	unsigned i;

	/* Zero out HW ring memory */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		rxq->rx_ring[i] = zeroed_desc;
	}

	rxq->rx_tail = 0;
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;

	rxq->head_ptr = 0;
    rxq->tail_ptr = 0;
    rxq->clean_tail_ptr = 0;
}

uint64_t
mqnic_get_rx_port_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t rx_offload_capa = 0;
	RTE_SET_USED(dev);

	return rx_offload_capa;
}

uint64_t
mqnic_get_rx_queue_offloads_capa(struct rte_eth_dev *dev)
{
	uint64_t rx_queue_offload_capa;
	RTE_SET_USED(dev);
	rx_queue_offload_capa = 0;

	return rx_queue_offload_capa;
}

int
eth_mqnic_rx_queue_setup(struct rte_eth_dev *dev,
			 uint16_t queue_idx,
			 uint16_t nb_desc,
			 unsigned int socket_id,
			 const struct rte_eth_rxconf *rx_conf,
			 struct rte_mempool *mp)
{
	const struct rte_memzone *rz;
	struct mqnic_rx_queue *rxq;
	uint64_t offloads;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	offloads = rx_conf->offloads | dev->data->dev_conf.rxmode.offloads;

	/*
	 * Validate number of receive descriptors.
	 * It must not exceed hardware maximum, and must be multiple
	 * of MQNIC_ALIGN.
	 */
	if (nb_desc % IGB_RXD_ALIGN != 0 ||
			(nb_desc > MQNIC_MAX_RING_DESC) ||
			(nb_desc < MQNIC_MIN_RING_DESC)) {
			PMD_INIT_LOG(INFO, "nb_desc(%d) must > %d and < %d.",
				nb_desc, MQNIC_MIN_RING_DESC, MQNIC_MAX_RING_DESC);
		return -EINVAL;
	}

	/* Free memory prior to re-allocation if needed */
	if (dev->data->rx_queues[queue_idx] != NULL) {
		mqnic_rx_queue_release(dev->data->rx_queues[queue_idx]);
		dev->data->rx_queues[queue_idx] = NULL;
	}

	/* First allocate the RX queue data structure. */
	rxq = rte_zmalloc("ethdev RX queue", sizeof(struct mqnic_rx_queue),
			  RTE_CACHE_LINE_SIZE);
	if (rxq == NULL)
		return -ENOMEM;

	rxq->size = roundup_pow_of_two(nb_desc);
	rxq->full_size = rxq->size >> 1;
    rxq->size_mask = rxq->size-1;
    rxq->stride = roundup_pow_of_two(MQNIC_DESC_SIZE);

    rxq->desc_block_size = rxq->stride/MQNIC_DESC_SIZE;
    rxq->log_desc_block_size = rxq->desc_block_size < 2 ? 0 : ilog2(rxq->desc_block_size-1)+1;
    rxq->desc_block_size = 1 << rxq->log_desc_block_size;

	rxq->buf_size = rxq->size*rxq->stride;

	rxq->offloads = offloads;
	rxq->mb_pool = mp;
	rxq->nb_rx_desc = rxq->size;

	rxq->drop_en = rx_conf->rx_drop_en;
	rxq->rx_free_thresh = rx_conf->rx_free_thresh;
	rxq->queue_id = queue_idx;
	rxq->reg_idx = queue_idx;
	rxq->port_id = dev->data->port_id;
	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_KEEP_CRC)
		rxq->crc_len = RTE_ETHER_CRC_LEN;
	else
		rxq->crc_len = 0;

	/*
	 *  Allocate RX ring hardware descriptors. A memzone large enough to
	 *  handle the maximum ring size is allocated in order to allow for
	 *  resizing in later calls to the queue setup function.
	 */
	rz = rte_eth_dma_zone_reserve(dev, "rx_ring", queue_idx, rxq->buf_size,
				      MQNIC_ALIGN, socket_id);
	if (rz == NULL) {
		mqnic_rx_queue_release(rxq);
		return -ENOMEM;
	}

	rxq->hw_addr = priv->hw_addr+priv->rx_queue_offset+queue_idx*MQNIC_QUEUE_STRIDE;
    rxq->hw_ptr_mask = 0xffff;
    rxq->hw_head_ptr = rxq->hw_addr+MQNIC_QUEUE_HEAD_PTR_REG;
    rxq->hw_tail_ptr = rxq->hw_addr+MQNIC_QUEUE_TAIL_PTR_REG;

    rxq->head_ptr = 0;
    rxq->tail_ptr = 0;
    rxq->clean_tail_ptr = 0;

	rxq->rx_ring_phys_addr = rz->iova;
	rxq->rx_ring = (struct mqnic_desc *) rz->addr;

	/* Allocate software ring. */
	rxq->sw_ring = rte_zmalloc("rxq->sw_ring",
				   sizeof(struct mqnic_rx_entry) * rxq->nb_rx_desc,
				   RTE_CACHE_LINE_SIZE);
	if (rxq->sw_ring == NULL) {
		PMD_INIT_LOG(ERR, "failed to alloc sw_ring");
		mqnic_rx_queue_release(rxq);
		return -ENOMEM;
	}
	PMD_INIT_LOG(DEBUG, "rx sw_ring=%p hw_ring=%p dma_addr=0x%"PRIx64,
		     rxq->sw_ring, rxq->rx_ring, rxq->rx_ring_phys_addr);

	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    // set base address
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+0, rxq->rx_ring_phys_addr);
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+4, rxq->rx_ring_phys_addr >> 32);
    // set completion queue index
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_CPL_QUEUE_INDEX_REG, 0);
    // set pointers
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_HEAD_PTR_REG, rxq->head_ptr & rxq->hw_ptr_mask);
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_TAIL_PTR_REG, rxq->tail_ptr & rxq->hw_ptr_mask);
    // set size
	MQNIC_DIRECT_WRITE_REG(rxq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(rxq->size) | (rxq->log_desc_block_size << 8));

	dev->data->rx_queues[queue_idx] = rxq;
	mqnic_reset_rx_queue(rxq);

	return 0;
}

void
mqnic_dev_clear_queues(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct mqnic_tx_queue *txq;
	struct mqnic_rx_queue *rxq;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (txq != NULL) {
			mqnic_tx_queue_release_mbufs(txq);
			mqnic_reset_tx_queue(txq, dev);
		}
	}

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		rxq = dev->data->rx_queues[i];
		if (rxq != NULL) {
			mqnic_rx_queue_release_mbufs(rxq);
			mqnic_reset_rx_queue(rxq);
		}
	}
}

void
mqnic_dev_free_queues(struct rte_eth_dev *dev)
{
	uint16_t i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		eth_mqnic_rx_queue_release(dev->data->rx_queues[i]);
		dev->data->rx_queues[i] = NULL;
		rte_eth_dma_zone_free(dev, "rx_ring", i);
	}
	dev->data->nb_rx_queues = 0;

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		eth_mqnic_tx_queue_release(dev->data->tx_queues[i]);
		dev->data->tx_queues[i] = NULL;
		rte_eth_dma_zone_free(dev, "tx_ring", i);
	}
	dev->data->nb_tx_queues = 0;
}

void
mqnic_dev_deactive_queues(struct rte_eth_dev *dev)
{
	uint16_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		mqnic_deactivate_rx_queue(dev->data->rx_queues[i]);
	}

	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		mqnic_deactivate_tx_queue(dev->data->tx_queues[i]);
	}
	MQNIC_WRITE_FLUSH(priv);
}

/*********************************************************************
 *
 *  Enable receive unit.
 *
 **********************************************************************/

static int
mqnic_alloc_rx_queue_mbufs(struct mqnic_rx_queue *rxq)
{
	struct mqnic_rx_entry *rxe = rxq->sw_ring;
	uint64_t dma_addr;
	unsigned i;

	/* Initialize software ring entries. */
	for (i = 0; i < rxq->nb_rx_desc; i++) {
		volatile struct mqnic_desc *rxd;
		struct rte_mbuf *mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);

		if (mbuf == NULL) {
			PMD_INIT_LOG(ERR, "RX mbuf alloc failed "
				     "queue_id=%hu", rxq->queue_id);
			return -ENOMEM;
		}
		dma_addr =
			rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
		rxd = &rxq->rx_ring[i];
		rxd->len = mbuf->buf_len; //right????????
		rxd->addr = dma_addr;
		rxe[i].mbuf = mbuf;

		rxq->head_ptr++;

		if((rxq->head_ptr == 1) || (rxq->head_ptr == rxq->nb_rx_desc)){
			PMD_INIT_LOG(DEBUG, "rxd->len = mbuf->buf_len = %d, dma_addr=0x%lx, rxq->head_ptr=%d", 
				mbuf->buf_len, dma_addr, rxq->head_ptr);
		}
	}

	return 0;
}

int
eth_mqnic_rx_init(struct rte_eth_dev *dev)
{
	struct mqnic_rx_queue *rxq;
	uint16_t i;
	int ret;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "eth_mqnic_rx_init");

	/* Configure and enable each RX queue. */
	dev->rx_pkt_burst = eth_mqnic_recv_pkts;
	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		//uint64_t bus_addr;
		//uint32_t rxdctl;

		rxq = dev->data->rx_queues[i];
		if (rxq == NULL) {
			PMD_INIT_LOG(ERR, "invalid rx queue buffer, i = %d.", i);
			return -1;
		}

		rxq->flags = 0;
		rxq->priv = priv;

		/* Allocate buffers for descriptor rings and set up queue */
		ret = mqnic_alloc_rx_queue_mbufs(rxq);
		if (ret)
			return ret;

		mqnic_activate_rxq(rxq, i);
		MQNIC_WRITE_FLUSH(priv);
		// enqueue on NIC
		mqnic_rx_write_head_ptr(rxq);
		MQNIC_WRITE_FLUSH(priv);
	}

	if (dev->data->dev_conf.rxmode.offloads & DEV_RX_OFFLOAD_SCATTER) {
		if (!dev->data->scattered_rx)
			PMD_INIT_LOG(DEBUG, "forcing scatter mode");
		dev->rx_pkt_burst = eth_mqnic_recv_scattered_pkts;
		dev->data->scattered_rx = 1;
	}

	return 0;
}

/*********************************************************************
 *
 *  Enable transmit unit.
 *
 **********************************************************************/
void
eth_mqnic_tx_init(struct rte_eth_dev *dev)
{
	struct mqnic_tx_queue *txq;
	uint16_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "eth_mqnic_tx_init");

	/* Setup the Base and Length of the Tx Descriptor Rings. */
	for (i = 0; i < dev->data->nb_tx_queues; i++) {
		txq = dev->data->tx_queues[i];
		if (txq == NULL) {
			PMD_INIT_LOG(ERR, "invalid tx queue buffer, i = %d.", i);
			return;
		}
		txq->cpl_index = i;
		txq->priv = priv;

		// deactivate queue
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    	// set base address
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+0, txq->tx_ring_phys_addr);
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_BASE_ADDR_REG+4, txq->tx_ring_phys_addr >> 32);
    	// set completion queue index
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_CPL_QUEUE_INDEX_REG, txq->cpl_index);
    	// set pointers
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_HEAD_PTR_REG, txq->head_ptr & txq->hw_ptr_mask);
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_TAIL_PTR_REG, txq->tail_ptr & txq->hw_ptr_mask);
    	// set size and activate queue
		MQNIC_DIRECT_WRITE_REG(txq->hw_addr, MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(txq->size) | (txq->log_desc_block_size << 8) | MQNIC_QUEUE_ACTIVE_MASK);
	}
}

void
mqnic_rxq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_rxq_info *qinfo)
{
	struct mqnic_rx_queue *rxq;

	rxq = dev->data->rx_queues[queue_id];

	qinfo->mp = rxq->mb_pool;
	qinfo->scattered_rx = dev->data->scattered_rx;
	qinfo->nb_desc = rxq->nb_rx_desc;

	qinfo->conf.rx_free_thresh = rxq->rx_free_thresh;
	qinfo->conf.rx_drop_en = rxq->drop_en;
	qinfo->conf.offloads = rxq->offloads;
}

void
mqnic_txq_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
	struct rte_eth_txq_info *qinfo)
{
	struct mqnic_tx_queue *txq;

	txq = dev->data->tx_queues[queue_id];

	qinfo->nb_desc = txq->nb_tx_desc;

	qinfo->conf.tx_thresh.pthresh = txq->pthresh;
	qinfo->conf.tx_thresh.hthresh = txq->hthresh;
	qinfo->conf.tx_thresh.wthresh = txq->wthresh;
	qinfo->conf.offloads = txq->offloads;
}

