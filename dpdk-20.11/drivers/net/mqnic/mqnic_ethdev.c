/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Bruce
 */

#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <rte_string_fns.h>
#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_pci.h>
#include <rte_bus_pci.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_ethdev_pci.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_malloc.h>
#include <rte_dev.h>

#include "mqnic_hw.h"
#include "mqnic_logs.h"
#include "mqnic_defines.h"
#include "mqnic_ethdev.h"
#include "mqnic_regs.h"

/*
 * Default values for port configuration
 */
#define IGB_DEFAULT_RX_FREE_THRESH  32

#define IGB_DEFAULT_RX_PTHRESH     8
#define IGB_DEFAULT_RX_HTHRESH      8
#define IGB_DEFAULT_RX_WTHRESH     4

#define IGB_DEFAULT_TX_PTHRESH     8
#define IGB_DEFAULT_TX_HTHRESH      1
#define IGB_DEFAULT_TX_WTHRESH     16

/* External VLAN Enable bit mask */
#define MQNIC_CTRL_EXT_EXT_VLAN      (1 << 26)

/* MSI-X other interrupt vector */
#define IGB_MSIX_OTHER_INTR_VEC      0

static int  eth_mqnic_configure(struct rte_eth_dev *dev);
static int  eth_mqnic_start(struct rte_eth_dev *dev);
static int  eth_mqnic_stop(struct rte_eth_dev *dev);
static int eth_mqnic_close(struct rte_eth_dev *dev);
static int eth_mqnic_reset(struct rte_eth_dev *dev);
static int  eth_mqnic_promiscuous_enable(struct rte_eth_dev *dev);
static int  eth_mqnic_promiscuous_disable(struct rte_eth_dev *dev);
static int  eth_mqnic_link_update(struct rte_eth_dev *dev,
				int wait_to_complete);

static int eth_mqnic_stats_get(struct rte_eth_dev *dev,
				struct rte_eth_stats *rte_stats);
static int eth_mqnic_stats_reset(struct rte_eth_dev *dev);
static int eth_mqnic_infos_get(struct rte_eth_dev *dev,
			      struct rte_eth_dev_info *dev_info);
static const uint32_t *eth_mqnic_supported_ptypes_get(struct rte_eth_dev *dev);
static int  eth_mqnic_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);

/*
 * Define VF Stats MACRO for Non "cleared on read" register
 */
#define UPDATE_VF_STAT(reg, last, cur)            \
{                                                 \
	u32 latest = MQNIC_READ_REG(hw, reg);     \
	cur += (latest - last) & UINT_MAX;        \
	last = latest;                            \
}

#define IGB_FC_PAUSE_TIME 0x0680
#define IGB_LINK_UPDATE_CHECK_TIMEOUT  90  /* 9s */
#define IGB_LINK_UPDATE_CHECK_INTERVAL 100 /* ms */

#define IGBVF_PMD_NAME "rte_igbvf_pmd"     /* PMD name */

/*
 * The set of PCI devices this driver supports
 */
static const struct rte_pci_id pci_id_mqnic_map[] = {
	{ RTE_PCI_DEVICE(MQNIC_INTEL_VENDOR_ID, MQNIC_DEV_ID) },
	{ .vendor_id = 0, /* sentinel */ },
};

static const struct rte_eth_desc_lim rx_desc_lim = {
	.nb_max = MQNIC_MAX_RING_DESC,
	.nb_min = MQNIC_MIN_RING_DESC,
	.nb_align = IGB_RXD_ALIGN,
};

static const struct rte_eth_desc_lim tx_desc_lim = {
	.nb_max = MQNIC_MAX_RING_DESC,
	.nb_min = MQNIC_MIN_RING_DESC,
	.nb_align = IGB_RXD_ALIGN,
	.nb_seg_max = IGB_TX_MAX_SEG,
	.nb_mtu_seg_max = IGB_TX_MAX_MTU_SEG,
};

static const struct eth_dev_ops eth_mqnic_ops = {
	.dev_configure        = eth_mqnic_configure,
	.dev_start            = eth_mqnic_start,
	.dev_stop             = eth_mqnic_stop,
	.dev_close            = eth_mqnic_close,
	.dev_reset            = eth_mqnic_reset,
	.promiscuous_enable   = eth_mqnic_promiscuous_enable,
	.promiscuous_disable  = eth_mqnic_promiscuous_disable,
	.link_update          = eth_mqnic_link_update,
	.stats_get            = eth_mqnic_stats_get,
	.stats_reset          = eth_mqnic_stats_reset,
	.dev_infos_get        = eth_mqnic_infos_get,
	.dev_supported_ptypes_get = eth_mqnic_supported_ptypes_get,
	.mtu_set              = eth_mqnic_mtu_set,
	.rx_queue_setup       = eth_mqnic_rx_queue_setup,
	.rx_queue_release     = eth_mqnic_rx_queue_release,
	.tx_queue_setup       = eth_mqnic_tx_queue_setup,
	.tx_queue_release     = eth_mqnic_tx_queue_release,
	.tx_done_cleanup      = eth_mqnic_tx_done_cleanup,
	.rxq_info_get         = mqnic_rxq_info_get,
	.txq_info_get         = mqnic_txq_info_get,
};

static void
mqnic_event_queue_release(struct mqnic_eq_ring *ring)
{
	if (ring != NULL) {
		rte_free(ring);
	}
}

static int
mqnic_all_event_queue_create(struct rte_eth_dev *dev, int socket_id)
{
	const struct rte_memzone *tz;
	struct mqnic_eq_ring *ring;
	uint32_t event_queue_size = 1024;   //number of event queue
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_all_event_queue_create");

	for (i = 0; i < priv->event_queue_count; i++){
		/* Free memory prior to re-allocation if needed */
		if (priv->event_ring[i] != NULL) {
			PMD_INIT_LOG(DEBUG, "release event ring %d", i);
			mqnic_event_queue_release(priv->event_ring[i]);
			priv->event_ring[i] = NULL;
		}

		/* allocate the event queue data structure */
		ring = rte_zmalloc("ethdev event queue", sizeof(struct mqnic_eq_ring),
							RTE_CACHE_LINE_SIZE);
		if (ring == NULL){
			PMD_INIT_LOG(ERR, "failed to alloc event queue");
			return -ENOMEM;
		}

		ring->size = roundup_pow_of_two(event_queue_size);
		ring->size_mask = ring->size-1;
		ring->stride = roundup_pow_of_two(MQNIC_EVENT_SIZE);

		ring->buf_size = ring->size*ring->stride;
		tz = rte_eth_dma_zone_reserve(dev, "event_ring", i, ring->buf_size,
				      MQNIC_ALIGN, socket_id);
		if (tz == NULL) {
			PMD_INIT_LOG(ERR, "failed to alloc event ring buffer, i = %d.", i);
			rte_free(ring);
			return -ENOMEM;
		}
		ring->buf = (u8*)tz->addr;
		ring->buf_dma_addr = tz->iova;

    	ring->hw_addr = priv->hw_addr+priv->event_queue_offset+i*MQNIC_EVENT_QUEUE_STRIDE;
    	ring->hw_ptr_mask = 0xffff;
    	ring->hw_head_ptr = ring->hw_addr+MQNIC_EVENT_QUEUE_HEAD_PTR_REG;
    	ring->hw_tail_ptr = ring->hw_addr+MQNIC_EVENT_QUEUE_TAIL_PTR_REG;

    	ring->head_ptr = 0;
    	ring->tail_ptr = 0;

		PMD_INIT_LOG(DEBUG, "ring->buf=%p ring->hw_addr=%p ring->buf_dma_addr=0x%"PRIx64,
		     ring->buf, ring->hw_addr, ring->buf_dma_addr);

		// deactivate queue
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    	// set base address
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_BASE_ADDR_REG+0, ring->buf_dma_addr);
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_BASE_ADDR_REG+4, ring->buf_dma_addr >> 32);
    	// set interrupt index
    	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_INTERRUPT_INDEX_REG, 0);
    	// set pointers
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_HEAD_PTR_REG, ring->head_ptr & ring->hw_ptr_mask);
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_TAIL_PTR_REG, ring->tail_ptr & ring->hw_ptr_mask);
		// set size
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));

		priv->event_ring[i] = ring;
	}
	MQNIC_WRITE_FLUSH(priv);

	return 0;
}

static void
mqnic_all_event_queue_destroy(struct rte_eth_dev *dev)
{
	struct mqnic_eq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_all_event_queue_destroy");

	for (i = 0; i < priv->event_queue_count; i++){
		/* Free memory prior to re-allocation if needed */
		if (priv->event_ring[i] != NULL) {
			ring = priv->event_ring[i];
			// deactivate queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
			// disarm queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_INTERRUPT_INDEX_REG, ring->int_index);
			MQNIC_WRITE_FLUSH(priv);
			PMD_INIT_LOG(DEBUG, "release event ring %d", i);
			mqnic_event_queue_release(priv->event_ring[i]);
			priv->event_ring[i] = NULL;
		}

		rte_eth_dma_zone_free(dev, "event_ring", i);
	}

	return;
}

static void
mqnic_all_event_queue_deactivate(struct rte_eth_dev *dev)
{
	struct mqnic_eq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_all_event_queue_deactivate");

	for (i = 0; i < priv->event_queue_count; i++){
		/* Free memory prior to re-allocation if needed */
		if (priv->event_ring[i] != NULL) {
			ring = priv->event_ring[i];
			// deactivate queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
			// disarm queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_INTERRUPT_INDEX_REG, ring->int_index);
			MQNIC_WRITE_FLUSH(priv);
		}
	}

	return;
}

static void mqnic_arm_eq(struct mqnic_eq_ring *ring)
{
	//PMD_INIT_LOG(DEBUG, "skip arm eq, int_index = %d!!", ring->int_index);
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_INTERRUPT_INDEX_REG, ring->int_index | MQNIC_EVENT_QUEUE_ARM_MASK);
}

static int
mqnic_all_event_queue_active(struct rte_eth_dev *dev)
{
	struct mqnic_eq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	int int_index = 0; //only one interrupt
	
	PMD_INIT_LOG(DEBUG, "mqnic_all_event_queue_active");

	for (i = 0; i < priv->event_queue_count; i++){
		ring = priv->event_ring[i];
		/* Free memory prior to re-allocation if needed */
		if (ring == NULL) {
			PMD_INIT_LOG(ERR, "invalid event ring buffer, i = %d.", i);
			return -1;
		}
		ring->int_index = int_index;

		// deactivate queue
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    	// set base address
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_BASE_ADDR_REG+0, ring->buf_dma_addr);
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_BASE_ADDR_REG+4, ring->buf_dma_addr >> 32);
  		// set interrupt index
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_INTERRUPT_INDEX_REG, ring->int_index);
		// set pointers
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_HEAD_PTR_REG, ring->head_ptr & ring->hw_ptr_mask);
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_TAIL_PTR_REG, ring->tail_ptr & ring->hw_ptr_mask);
    	// set size and activate queue
		MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_EVENT_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size) | MQNIC_EVENT_QUEUE_ACTIVE_MASK);

		mqnic_arm_eq(ring);
	}
	MQNIC_WRITE_FLUSH(priv);

	return 0;
}

void mqnic_arm_cq(struct mqnic_cq_ring *ring)
{
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, ring->eq_index | MQNIC_CPL_QUEUE_ARM_MASK);
}

static void mqnic_active_cpl_queue_registers(struct mqnic_cq_ring *ring)
{
	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    // set base address
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_BASE_ADDR_REG+0, ring->buf_dma_addr);
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_BASE_ADDR_REG+4, ring->buf_dma_addr >> 32);
	// set interrupt index
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, ring->eq_index);
	// set pointers
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_HEAD_PTR_REG, ring->head_ptr & ring->hw_ptr_mask);
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_TAIL_PTR_REG, ring->tail_ptr & ring->hw_ptr_mask);
	// set size and activate queue
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size) | MQNIC_CPL_QUEUE_ACTIVE_MASK);
}

static void
mqnic_tx_cpl_queue_active(struct rte_eth_dev *dev)
{
	struct mqnic_cq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	PMD_INIT_LOG(DEBUG, "mqnic_tx_cpl_queue_active");

	for (i = 0; i < priv->tx_cpl_queue_count; i++){
		ring = priv->tx_cpl_ring[i];

		if (ring == NULL) {
			PMD_INIT_LOG(ERR, "invalid tx cpl ring buffer, i = %d.", i);
			return;
		}
		ring->eq_index = i % priv->event_queue_count;
		ring->ring_index = i;

		mqnic_active_cpl_queue_registers(ring);
		mqnic_arm_cq(ring);
	}

	MQNIC_WRITE_FLUSH(priv);
	return;
}

static void
mqnic_rx_cpl_queue_active(struct rte_eth_dev *dev)
{
	struct mqnic_cq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	PMD_INIT_LOG(DEBUG, "mqnic_rx_cpl_queue_active");

	for (i = 0; i < priv->rx_cpl_queue_count; i++){
		ring = priv->rx_cpl_ring[i];

		if (ring == NULL) {
			PMD_INIT_LOG(ERR, "invalid rx cpl ring buffer, i = %d.", i);
			return;
		}
		ring->eq_index = i % priv->event_queue_count;
		ring->ring_index = i;

		mqnic_active_cpl_queue_registers(ring);
		mqnic_arm_cq(ring);
	}

	MQNIC_WRITE_FLUSH(priv);
	return;
}


static void 
mqnic_init_cpl_queue_registers(struct mqnic_cq_ring *ring)
{
	// deactivate queue
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, 0);
    // set base address
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_BASE_ADDR_REG+0, ring->buf_dma_addr);
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_BASE_ADDR_REG+4, ring->buf_dma_addr >> 32);
    // set interrupt index
    MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, 0);
    // set pointers
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_HEAD_PTR_REG, ring->head_ptr & ring->hw_ptr_mask);
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_TAIL_PTR_REG, ring->tail_ptr & ring->hw_ptr_mask);
	// set size
	MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
}

static int
mqnic_tx_cpl_queue_create(struct rte_eth_dev *dev, int socket_id)
{
	const struct rte_memzone *tz;
	struct mqnic_cq_ring *ring;
	uint32_t cpl_queue_size = 512;   //number of event queue
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_tx_cpl_queue_create");

	for (i = 0; i < priv->tx_cpl_queue_count; i++){

		if (priv->tx_cpl_ring[i] != NULL) {
			PMD_INIT_LOG(DEBUG, "release tx cpl ring %d", i);
			mqnic_cpl_queue_release(priv->tx_cpl_ring[i]);
			priv->tx_cpl_ring[i] = NULL;
		}

		/* allocate the event queue data structure */
		ring = rte_zmalloc("ethdev tx cpl queue", sizeof(struct mqnic_cq_ring),
							RTE_CACHE_LINE_SIZE);
		if (ring == NULL){
			PMD_INIT_LOG(ERR, "failed to alloc tx cpl queue");
			return -ENOMEM;
		}

		ring->size = roundup_pow_of_two(cpl_queue_size);
		ring->size_mask = ring->size-1;
		ring->stride = roundup_pow_of_two(MQNIC_CPL_SIZE);

		ring->buf_size = ring->size*ring->stride;
		tz = rte_eth_dma_zone_reserve(dev, "tx_cq_ring", i, ring->buf_size,
				      MQNIC_ALIGN, socket_id);
		if (tz == NULL) {
			PMD_INIT_LOG(ERR, "failed to alloc tx cq ring buffer, i = %d, buf_size = 0x%lx, size = 0x%x, stride = 0x%x", i, ring->buf_size, ring->size, ring->stride);
			rte_free(ring);
			return -ENOMEM;
		}
		ring->buf = (u8*)tz->addr;
		ring->buf_dma_addr = tz->iova;

    	ring->hw_addr = priv->hw_addr+priv->tx_cpl_queue_offset+i*MQNIC_CPL_QUEUE_STRIDE;
    	ring->hw_ptr_mask = 0xffff;
    	ring->hw_head_ptr = ring->hw_addr+MQNIC_CPL_QUEUE_HEAD_PTR_REG;
    	ring->hw_tail_ptr = ring->hw_addr+MQNIC_CPL_QUEUE_TAIL_PTR_REG;

    	ring->head_ptr = 0;
    	ring->tail_ptr = 0;

		PMD_INIT_LOG(DEBUG, "tx ring->buf=%p ring->hw_addr=%p ring->buf_dma_addr=0x%"PRIx64,
		     ring->buf, ring->hw_addr, ring->buf_dma_addr);

		mqnic_init_cpl_queue_registers(ring);

		priv->tx_cpl_ring[i] = ring;
	}

	MQNIC_WRITE_FLUSH(priv);
	return 0;
}

static void
mqnic_tx_cpl_queue_destroy(struct rte_eth_dev *dev)
{
	//const struct rte_memzone *tz;
	struct mqnic_cq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_tx_cpl_queue_destroy");

	for (i = 0; i < priv->tx_cpl_queue_count; i++){

		if (priv->tx_cpl_ring[i] != NULL) {
			ring = priv->tx_cpl_ring[i];
			// deactivate queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
    		// disarm queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, ring->eq_index);
			MQNIC_WRITE_FLUSH(priv);
			PMD_INIT_LOG(DEBUG, "release tx cpl ring %d", i);
			mqnic_cpl_queue_release(ring);
			priv->tx_cpl_ring[i] = NULL;
		}

		rte_eth_dma_zone_free(dev, "tx_cq_ring", i);
	}

	return;
}

static void
mqnic_tx_cpl_queue_deactivate(struct rte_eth_dev *dev)
{
	//const struct rte_memzone *tz;
	struct mqnic_cq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_tx_cpl_queue_deactivate");

	for (i = 0; i < priv->tx_cpl_queue_count; i++){
		if (priv->tx_cpl_ring[i] != NULL) {
			ring = priv->tx_cpl_ring[i];
			// deactivate queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
    		// disarm queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, ring->eq_index);
			MQNIC_WRITE_FLUSH(priv);
		}
	}

	return;
}

static int
mqnic_rx_cpl_queue_create(struct rte_eth_dev *dev, int socket_id)
{
	const struct rte_memzone *tz;
	struct mqnic_cq_ring *ring;
	uint32_t cpl_queue_size = 256;   //number of event queue
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_rx_cpl_queue_create");

	for (i = 0; i < priv->rx_cpl_queue_count; i++){
		/* Free memory prior to re-allocation if needed */
		if (priv->rx_cpl_ring[i] != NULL) {
			PMD_INIT_LOG(DEBUG, "release rx cpl ring %d", i);
			mqnic_cpl_queue_release(priv->rx_cpl_ring[i]);
			priv->rx_cpl_ring[i] = NULL;
		}

		/* allocate the event queue data structure */
		ring = rte_zmalloc("ethdev rx cpl queue", sizeof(struct mqnic_cq_ring),
							RTE_CACHE_LINE_SIZE);
		if (ring == NULL){
			PMD_INIT_LOG(ERR, "failed to alloc rx cpl queue");
			return -ENOMEM;
		}

		ring->size = roundup_pow_of_two(cpl_queue_size);
		ring->size_mask = ring->size-1;
		ring->stride = roundup_pow_of_two(MQNIC_CPL_SIZE);

		ring->buf_size = ring->size*ring->stride;
		tz = rte_eth_dma_zone_reserve(dev, "rx_cq_ring", i, ring->buf_size,
				      MQNIC_ALIGN, socket_id);
		if (tz == NULL) {
			PMD_INIT_LOG(ERR, "failed to alloc rx cq ring buffer, i = %d, buf_size = 0x%lx, size = 0x%x, stride = 0x%x", i, ring->buf_size, ring->size, ring->stride);
			rte_free(ring);
			return -ENOMEM;
		}
		ring->buf = (u8*)tz->addr;
		ring->buf_dma_addr = tz->iova;

    	ring->hw_addr = priv->hw_addr+priv->rx_cpl_queue_offset+i*MQNIC_CPL_QUEUE_STRIDE;
    	ring->hw_ptr_mask = 0xffff;
    	ring->hw_head_ptr = ring->hw_addr+MQNIC_CPL_QUEUE_HEAD_PTR_REG;
    	ring->hw_tail_ptr = ring->hw_addr+MQNIC_CPL_QUEUE_TAIL_PTR_REG;

    	ring->head_ptr = 0;
    	ring->tail_ptr = 0;

		PMD_INIT_LOG(DEBUG, "rx ring->buf=%p ring->hw_addr=%p ring->buf_dma_addr=0x%"PRIx64,
		     ring->buf, ring->hw_addr, ring->buf_dma_addr);

		mqnic_init_cpl_queue_registers(ring);

		priv->rx_cpl_ring[i] = ring;
	}

	MQNIC_WRITE_FLUSH(priv);
	return 0;
}

static void
mqnic_rx_cpl_queue_destroy(struct rte_eth_dev *dev)
{
	//const struct rte_memzone *tz;
	struct mqnic_cq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_rx_cpl_queue_destroy");

	for (i = 0; i < priv->rx_cpl_queue_count; i++){
		/* Free memory prior to re-allocation if needed */
		if (priv->rx_cpl_ring[i] != NULL) {
			ring = priv->rx_cpl_ring[i];
			// deactivate queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
    		// disarm queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, ring->eq_index);
			MQNIC_WRITE_FLUSH(priv);
			PMD_INIT_LOG(DEBUG, "release rx cpl ring %d", i);
			mqnic_cpl_queue_release(ring);
			priv->rx_cpl_ring[i] = NULL;
		}

		rte_eth_dma_zone_free(dev, "rx_cq_ring", i);
	}

	return;
}

static void
mqnic_rx_cpl_queue_deactivate(struct rte_eth_dev *dev)
{
	//const struct rte_memzone *tz;
	struct mqnic_cq_ring *ring;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "mqnic_rx_cpl_queue_deactivate");

	for (i = 0; i < priv->rx_cpl_queue_count; i++){
		/* Free memory prior to re-allocation if needed */
		if (priv->rx_cpl_ring[i] != NULL) {
			ring = priv->rx_cpl_ring[i];
			// deactivate queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_ACTIVE_LOG_SIZE_REG, ilog2(ring->size));
    		// disarm queue
			MQNIC_DIRECT_WRITE_REG(ring->hw_addr, MQNIC_CPL_QUEUE_INTERRUPT_INDEX_REG, ring->eq_index);
			MQNIC_WRITE_FLUSH(priv);
		}
	}

	return;
}

static void
mqnic_determine_desc_block_size(struct rte_eth_dev *dev)
{
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	MQNIC_DIRECT_WRITE_REG(priv->hw_addr, priv->tx_queue_offset+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0xf << 8);
	priv->max_desc_block_size = 1 << ((MQNIC_DIRECT_READ_REG(priv->hw_addr, priv->tx_queue_offset+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG) >> 8) & 0xf);
	MQNIC_DIRECT_WRITE_REG(priv->hw_addr, priv->tx_queue_offset+MQNIC_QUEUE_ACTIVE_LOG_SIZE_REG, 0);

    PMD_INIT_LOG(INFO, "Max desc block size: %d", priv->max_desc_block_size);

    priv->max_desc_block_size = priv->max_desc_block_size < MQNIC_MAX_FRAGS ? priv->max_desc_block_size : MQNIC_MAX_FRAGS;

    priv->desc_block_size = priv->max_desc_block_size < 4 ? priv->max_desc_block_size : 4;
}

static void mqnic_port_set_rss_mask(struct mqnic_port *port, u32 rss_mask)
{
	MQNIC_DIRECT_WRITE_REG(port->hw_addr, MQNIC_PORT_REG_RSS_MASK, rss_mask);
}

static void mqnic_deactivate_port(struct mqnic_port *port)
{
    // disable schedulers
	MQNIC_DIRECT_WRITE_REG(port->hw_addr, MQNIC_PORT_REG_SCHED_ENABLE, 0);
}

static int mqnic_activate_first_port(struct rte_eth_dev *dev)
{
    uint32_t k;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	struct mqnic_port *port = priv->ports[0];

    // enable schedulers
	MQNIC_DIRECT_WRITE_REG(port->hw_addr, MQNIC_PORT_REG_SCHED_ENABLE, 0xffffffff);

    // enable queues
    for (k = 0; k < port->tx_queue_count; k++)
    {
		MQNIC_DIRECT_WRITE_REG(port->hw_addr, port->sched_offset+k*4, 3);
    }
	MQNIC_WRITE_FLUSH(priv);

    return 0;
}

static void
mqnic_set_port_mtu(struct rte_eth_dev *dev, uint32_t mtu)
{
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	struct mqnic_port *port;

	for (i = 0; i < priv->port_count; i++){
		port = priv->ports[i];
		MQNIC_DIRECT_WRITE_REG(port->hw_addr, MQNIC_PORT_REG_TX_MTU, mtu+ETH_HLEN);
		MQNIC_DIRECT_WRITE_REG(port->hw_addr, MQNIC_PORT_REG_RX_MTU, mtu+ETH_HLEN);
	}
}

static int
mqnic_all_port_setup(struct rte_eth_dev *dev)
{
	struct mqnic_port *port;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	
	PMD_INIT_LOG(DEBUG, "eth_mqnic_all_port_setup");

	for (i = 0; i < priv->port_count; i++){
		/* allocate the event queue data structure */
		port = rte_zmalloc("ethdev port", sizeof(struct mqnic_port),
							RTE_CACHE_LINE_SIZE);
		if (port == NULL){
			PMD_INIT_LOG(ERR, "failed to alloc port");
			return -ENOMEM;
		}

		priv->ports[i] = port;

    	port->index = i;
    	port->tx_queue_count = priv->tx_queue_count;
    	port->hw_addr = priv->hw_addr+priv->port_offset+i*priv->port_stride;

		// read ID registers
		port->port_id = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_PORT_ID);
    	PMD_INIT_LOG(INFO, "Port ID: 0x%08x", port->port_id);
		port->port_features = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_PORT_FEATURES);
    	PMD_INIT_LOG(INFO, "Port features: 0x%08x", port->port_features);
		port->port_mtu = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_PORT_MTU);
    	PMD_INIT_LOG(INFO, "Port MTU: %d", port->port_mtu);

    	port->sched_count = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_SCHED_COUNT);
    	PMD_INIT_LOG(INFO, "Scheduler count: %d", port->sched_count);
    	port->sched_offset = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_SCHED_OFFSET);
    	PMD_INIT_LOG(INFO, "Scheduler offset: 0x%08x", port->sched_offset);
    	port->sched_stride = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_SCHED_STRIDE);
    	PMD_INIT_LOG(INFO, "Scheduler stride: 0x%08x", port->sched_stride);
    	port->sched_type = MQNIC_DIRECT_READ_REG(port->hw_addr, MQNIC_PORT_REG_SCHED_TYPE);
    	PMD_INIT_LOG(INFO, "Scheduler type: 0x%08x", port->sched_type);

		mqnic_deactivate_port(port);

		mqnic_port_set_rss_mask(port, 0xffffffff);
	}
	MQNIC_WRITE_FLUSH(priv);

	return 0;
}

static void
mqnic_all_port_disable(struct rte_eth_dev *dev)
{
	struct mqnic_port *port;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	PMD_INIT_LOG(DEBUG, "mqnic_all_port_disable");

	for (i = 0; i < priv->port_count; i++){
		if (priv->ports[i] != NULL) {
			port = priv->ports[i];
			mqnic_deactivate_port(port);
			MQNIC_WRITE_FLUSH(priv);
			PMD_INIT_LOG(DEBUG, "release port %d", i);
			rte_free(port);
			priv->ports[i] = NULL;
		}
	}

	return;
}

static void
mqnic_all_port_deactivate(struct rte_eth_dev *dev)
{
	struct mqnic_port *port;
	uint32_t i;
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	PMD_INIT_LOG(DEBUG, "mqnic_all_port_deactivate");

	for (i = 0; i < priv->port_count; i++){
		if (priv->ports[i] != NULL) {
			port = priv->ports[i];
			mqnic_deactivate_port(port);
			MQNIC_WRITE_FLUSH(priv);
		}
	}

	return;
}

static void
eth_mqnic_get_if_hw_info(struct rte_eth_dev *dev)
{
	struct mqnic_hw *hw =
		MQNIC_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	memset(priv, 0, sizeof(struct mqnic_priv));
	
	priv->port = 1;
	priv->port_up = false;
	
	priv->hw_addr = hw->hw_addr;
	priv->csr_hw_addr = priv->hw_addr+hw->if_csr_offset;
	
	// read ID registers
	priv->if_id = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_IF_ID);
	PMD_INIT_LOG(DEBUG, "IF ID: 0x%08x", priv->if_id);
	priv->if_features = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_IF_FEATURES);
	PMD_INIT_LOG(DEBUG, "IF features: 0x%08x", priv->if_features);
	
	priv->event_queue_count = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_EVENT_QUEUE_COUNT);
	PMD_INIT_LOG(DEBUG, "Event queue count: %d", priv->event_queue_count);
	priv->event_queue_offset = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_EVENT_QUEUE_OFFSET);
	PMD_INIT_LOG(DEBUG, "Event queue offset: 0x%08x", priv->event_queue_offset);
	priv->tx_queue_count = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_TX_QUEUE_COUNT);
	PMD_INIT_LOG(DEBUG, "TX queue count: %d", priv->tx_queue_count);
	priv->tx_queue_offset = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_TX_QUEUE_OFFSET);
	PMD_INIT_LOG(DEBUG, "TX queue offset: 0x%08x", priv->tx_queue_offset);
	priv->tx_cpl_queue_count = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_TX_CPL_QUEUE_COUNT);
	PMD_INIT_LOG(DEBUG, "TX completion queue count: %d", priv->tx_cpl_queue_count);
	priv->tx_cpl_queue_offset = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_TX_CPL_QUEUE_OFFSET);
	PMD_INIT_LOG(DEBUG, "TX completion queue offset: 0x%08x", priv->tx_cpl_queue_offset);
	priv->rx_queue_count = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_RX_QUEUE_COUNT);
	PMD_INIT_LOG(DEBUG, "RX queue count: %d", priv->rx_queue_count);
	priv->rx_queue_offset = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_RX_QUEUE_OFFSET);
	PMD_INIT_LOG(DEBUG, "RX queue offset: 0x%08x", priv->rx_queue_offset);
	priv->rx_cpl_queue_count = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_RX_CPL_QUEUE_COUNT);
	PMD_INIT_LOG(DEBUG, "RX completion queue count: %d", priv->rx_cpl_queue_count);
	priv->rx_cpl_queue_offset = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_RX_CPL_QUEUE_OFFSET);
	PMD_INIT_LOG(DEBUG, "RX completion queue offset: 0x%08x", priv->rx_cpl_queue_offset);
	priv->port_count = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_PORT_COUNT);
	PMD_INIT_LOG(DEBUG, "Port count: %d", priv->port_count);
	priv->port_offset = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_PORT_OFFSET);
	PMD_INIT_LOG(DEBUG, "Port offset: 0x%08x", priv->port_offset);
	priv->port_stride = MQNIC_READ_PRIV_CSR_REG(priv, MQNIC_IF_REG_PORT_STRIDE);
	PMD_INIT_LOG(DEBUG, "Port stride: 0x%08x", priv->port_stride);
	
	if (priv->event_queue_count > MQNIC_MAX_EVENT_RINGS)
		priv->event_queue_count = MQNIC_MAX_EVENT_RINGS;
	if (priv->tx_queue_count > MQNIC_MAX_TX_RINGS)
		priv->tx_queue_count = MQNIC_MAX_TX_RINGS;
	if (priv->tx_cpl_queue_count > MQNIC_MAX_TX_CPL_RINGS)
		priv->tx_cpl_queue_count = MQNIC_MAX_TX_CPL_RINGS;
	if (priv->rx_queue_count > MQNIC_MAX_RX_RINGS)
		priv->rx_queue_count = MQNIC_MAX_RX_RINGS;
	if (priv->rx_cpl_queue_count > MQNIC_MAX_RX_CPL_RINGS)
		priv->rx_cpl_queue_count = MQNIC_MAX_RX_CPL_RINGS;
	
	if (priv->port_count > MQNIC_MAX_PORTS)
		priv->port_count = MQNIC_MAX_PORTS;
}


static int32_t
mqnic_get_basic_info_from_hw(struct mqnic_hw *hw)
{
    // Read ID registers
    hw->fw_id = MQNIC_READ_REG(hw, MQNIC_REG_FW_ID);
    PMD_INIT_LOG(DEBUG, "FW ID: 0x%08x", hw->fw_id);
	if (hw->fw_id == 0xffffffff){
		PMD_INIT_LOG(ERR, "Deivce needs to be reset");
		return MQNIC_ERR_RESET;
	}

    hw->fw_ver = MQNIC_READ_REG(hw, MQNIC_REG_FW_VER);
    PMD_INIT_LOG(DEBUG, "FW version: %d.%d", hw->fw_ver >> 16, hw->fw_ver & 0xffff);
    hw->board_id = MQNIC_READ_REG(hw, MQNIC_REG_BOARD_ID);
    PMD_INIT_LOG(DEBUG, "Board ID: 0x%08x", hw->board_id);
    hw->board_ver = MQNIC_READ_REG(hw, MQNIC_REG_BOARD_VER);
    PMD_INIT_LOG(DEBUG, "Board version: %d.%d", hw->board_ver >> 16, hw->board_ver & 0xffff);

    hw->if_count = MQNIC_READ_REG(hw, MQNIC_REG_IF_COUNT);
    PMD_INIT_LOG(DEBUG, "IF count: %d", hw->if_count);
    hw->if_stride = MQNIC_READ_REG(hw, MQNIC_REG_IF_STRIDE);
    PMD_INIT_LOG(DEBUG, "IF stride: 0x%08x", hw->if_stride);
    hw->if_csr_offset = MQNIC_READ_REG(hw, MQNIC_REG_IF_CSR_OFFSET);
    PMD_INIT_LOG(DEBUG, "IF CSR offset: 0x%08x", hw->if_csr_offset);

	// check BAR size
    if (hw->if_count*hw->if_stride > hw->hw_regs_size)
    {
        PMD_INIT_LOG(ERR, "Invalid BAR configuration (%d IF * 0x%x > 0x%lx)", hw->if_count, hw->if_stride, hw->hw_regs_size);
		return MQNIC_ERR_CONFIG;
    }

	if (hw->if_count > MQNIC_MAX_IF)
        hw->if_count = MQNIC_MAX_IF;

	return MQNIC_SUCCESS;
}


static void
mqnic_identify_hardware(struct rte_eth_dev *dev, struct rte_pci_device *pci_dev)
{
	struct mqnic_hw *hw =
		MQNIC_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	hw->vendor_id = pci_dev->id.vendor_id;
	hw->device_id = pci_dev->id.device_id;
	hw->subsystem_vendor_id = pci_dev->id.subsystem_vendor_id;
	hw->subsystem_device_id = pci_dev->id.subsystem_device_id;
}

static s32 
mqnic_read_mac_addr(struct mqnic_hw *hw)
{
	rte_eth_random_addr(hw->mac.addr);

	/* Set Organizationally Unique Identifier (OUI) prefix */
	hw->mac.addr[0] = 0x00;
	hw->mac.addr[1] = 0xAA;
	hw->mac.addr[2] = 0xBB;

	return MQNIC_SUCCESS;
}

static int
eth_mqnic_dev_init(struct rte_eth_dev *eth_dev)
{
	int error = 0;
	struct rte_pci_device *pci_dev = RTE_ETH_DEV_TO_PCI(eth_dev);
	struct mqnic_hw *hw =
		MQNIC_DEV_PRIVATE_TO_HW(eth_dev->data->dev_private);
	struct mqnic_adapter *adapter =
		MQNIC_DEV_PRIVATE(eth_dev->data->dev_private);

	eth_dev->dev_ops = &eth_mqnic_ops;
	eth_dev->rx_pkt_burst = &eth_mqnic_recv_pkts;
	eth_dev->tx_pkt_burst = &eth_mqnic_xmit_pkts;

	/* for secondary processes, we don't initialise any further as primary
	 * has already done this work. Only check we don't need a different
	 * RX function */
	if (rte_eal_process_type() != RTE_PROC_PRIMARY){
		if (eth_dev->data->scattered_rx)
			eth_dev->rx_pkt_burst = &eth_mqnic_recv_scattered_pkts;
		return 0;
	}

	rte_eth_copy_pci_info(eth_dev, pci_dev);
	eth_dev->data->dev_flags |= RTE_ETH_DEV_AUTOFILL_QUEUE_XSTATS;

	hw->hw_addr = (void *)pci_dev->mem_resource[0].addr;
	hw->hw_regs_size = pci_dev->mem_resource[0].len;

	mqnic_identify_hardware(eth_dev, pci_dev);
	if (mqnic_get_basic_info_from_hw(hw) != MQNIC_SUCCESS) {
		error = -EIO;
		goto err_late;
	}

	hw->hw_addr = hw->hw_addr + 0*hw->if_stride;  //use interface 0
	eth_mqnic_get_if_hw_info(eth_dev);
	mqnic_determine_desc_block_size(eth_dev);

	mqnic_all_event_queue_create(eth_dev, 0);
	mqnic_tx_cpl_queue_create(eth_dev, 0);
	mqnic_rx_cpl_queue_create(eth_dev, 0);
	mqnic_all_port_setup(eth_dev);

	/* Read the permanent MAC address out of the EEPROM */
	if (mqnic_read_mac_addr(hw) != 0) {
		PMD_INIT_LOG(ERR, "EEPROM error while reading MAC address");
		error = -EIO;
		goto err_late;
	}

	/* Allocate memory for storing MAC addresses */
	eth_dev->data->mac_addrs = rte_zmalloc("mqnic",
		RTE_ETHER_ADDR_LEN, 0);
	if (eth_dev->data->mac_addrs == NULL) {
		PMD_INIT_LOG(ERR, "Failed to allocate %d bytes needed to "
						"store MAC addresses",
				RTE_ETHER_ADDR_LEN);
		error = -ENOMEM;
		goto err_late;
	}

	/* Copy the permanent MAC address */
	rte_ether_addr_copy((struct rte_ether_addr *)hw->mac.addr,
			&eth_dev->data->mac_addrs[0]);

	adapter->stopped = 0;

	PMD_INIT_LOG(DEBUG, "port_id %d vendorID=0x%x deviceID=0x%x",
		     eth_dev->data->port_id, pci_dev->id.vendor_id,
		     pci_dev->id.device_id);

	return 0;

err_late:
	return error;
}

static int
eth_mqnic_dev_uninit(struct rte_eth_dev *eth_dev)
{
	PMD_INIT_FUNC_TRACE();

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	eth_mqnic_close(eth_dev);

	return 0;
}

static int eth_mqnic_pci_probe(struct rte_pci_driver *pci_drv __rte_unused,
	struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_probe(pci_dev,
		sizeof(struct mqnic_adapter), eth_mqnic_dev_init);
}

static int eth_mqnic_pci_remove(struct rte_pci_device *pci_dev)
{
	return rte_eth_dev_pci_generic_remove(pci_dev, eth_mqnic_dev_uninit);
}

static struct rte_pci_driver rte_mqnic_pmd = {
	.id_table = pci_id_mqnic_map,
	.drv_flags = RTE_PCI_DRV_NEED_MAPPING,
	.probe = eth_mqnic_pci_probe,
	.remove = eth_mqnic_pci_remove,
};

static int
mqnic_check_mq_mode(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static int
eth_mqnic_configure(struct rte_eth_dev *dev)
{
	int ret;

	PMD_INIT_FUNC_TRACE();

	/* multipe queue mode checking */
	ret  = mqnic_check_mq_mode(dev);
	if (ret != 0) {
		PMD_INIT_LOG(ERR, "mqnic_check_mq_mode fails with %d.",
			    ret);
		return ret;
	}

	PMD_INIT_FUNC_TRACE();

	return 0;
}

static int
eth_mqnic_start(struct rte_eth_dev *dev)
{
	struct mqnic_adapter *adapter =
		MQNIC_DEV_PRIVATE(dev->data->dev_private);
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);
	int ret;

	PMD_INIT_FUNC_TRACE();
	adapter->stopped = 0;

	mqnic_all_event_queue_active(dev);
	mqnic_rx_cpl_queue_active(dev);

	/* This can fail when allocating mbufs for descriptor rings */
	ret = eth_mqnic_rx_init(dev);
	if (ret) {
		PMD_INIT_LOG(ERR, "Unable to initialize RX hardware");
		mqnic_dev_clear_queues(dev);
		return ret;
	}

	mqnic_tx_cpl_queue_active(dev);
	eth_mqnic_tx_init(dev);

	mqnic_set_port_mtu(dev, 1500);
	mqnic_activate_first_port(dev);
	priv->port_up = true;

	eth_mqnic_link_update(dev, 0);

	PMD_INIT_LOG(DEBUG, "<<");

	return 0;
}

/*********************************************************************
 *
 *  This routine disables all traffic on the adapter by issuing a
 *  global reset on the MAC.
 *
 **********************************************************************/
static int
eth_mqnic_stop(struct rte_eth_dev *dev)
{
	struct rte_eth_link link;
	struct mqnic_adapter *adapter =
		MQNIC_DEV_PRIVATE(dev->data->dev_private);

	if (adapter->stopped)
		return 0;

	mqnic_all_port_deactivate(dev);
	mqnic_dev_deactive_queues(dev);
	mqnic_tx_cpl_queue_deactivate(dev);
	mqnic_rx_cpl_queue_deactivate(dev);
	mqnic_all_event_queue_deactivate(dev);
	rte_delay_us_sleep(10000);
	mqnic_dev_clear_queues(dev);

	/* clear the recorded link status */
	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);

	adapter->stopped = true;
	dev->data->dev_started = 0;

	return 0;
}

static int
eth_mqnic_close(struct rte_eth_dev *dev)
{
	struct rte_eth_link link;
	int ret;

	if (rte_eal_process_type() != RTE_PROC_PRIMARY)
		return 0;

	ret = eth_mqnic_stop(dev);

	mqnic_all_port_disable(dev);
	mqnic_dev_free_queues(dev);
	mqnic_tx_cpl_queue_destroy(dev);
	mqnic_rx_cpl_queue_destroy(dev);
	mqnic_all_event_queue_destroy(dev);

	memset(&link, 0, sizeof(link));
	rte_eth_linkstatus_set(dev, &link);

	return ret;
}

/*
 * Reset PF device.
 */
static int
eth_mqnic_reset(struct rte_eth_dev *dev)
{
	int ret;

	/* When a DPDK PMD PF begin to reset PF port, it should notify all
	 * its VF to make them align with it. The detailed notification
	 * mechanism is PMD specific and is currently not implemented.
	 * To avoid unexpected behavior in VF, currently reset of PF with
	 * SR-IOV activation is not supported. It might be supported later.
	 */
	if (dev->data->sriov.active)
		return -ENOTSUP;

	ret = eth_mqnic_dev_uninit(dev);
	if (ret)
		return ret;

	ret = eth_mqnic_dev_init(dev);

	return ret;
}

static int
eth_mqnic_stats_get(struct rte_eth_dev *dev, struct rte_eth_stats *rte_stats)
{
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	if (rte_stats == NULL)
		return -EINVAL;

	rte_stats->ipackets = priv->ipackets;
	rte_stats->opackets = priv->opackets;
	rte_stats->ibytes   = priv->ibytes;
	rte_stats->obytes   = priv->obytes;

	return 0;
}

static int
eth_mqnic_stats_reset(struct rte_eth_dev *dev)
{
	struct mqnic_priv *priv =
		MQNIC_DEV_PRIVATE_TO_PRIV(dev->data->dev_private);

	priv->ipackets = 0;
	priv->opackets = 0;
	priv->ibytes = 0;
	priv->obytes = 0;

	return 0;
}

static int
eth_mqnic_infos_get(struct rte_eth_dev *dev, struct rte_eth_dev_info *dev_info)
{

	dev_info->min_rx_bufsize = 256; /* See BSIZE field of RCTL register. */
	dev_info->max_rx_pktlen  = 0x1000;//0x3FFF; /* See RLPML register. */
	dev_info->max_mac_addrs = 1;//hw->mac.rar_entry_count;
	dev_info->rx_queue_offload_capa = mqnic_get_rx_queue_offloads_capa(dev);
	dev_info->rx_offload_capa = mqnic_get_rx_port_offloads_capa(dev) |
				    dev_info->rx_queue_offload_capa;
	dev_info->tx_queue_offload_capa = mqnic_get_tx_queue_offloads_capa(dev);
	dev_info->tx_offload_capa = mqnic_get_tx_port_offloads_capa(dev) |
				    dev_info->tx_queue_offload_capa;

	dev_info->max_rx_queues = 16;
	dev_info->max_tx_queues = 16;

	dev_info->max_vmdq_pools = 0;

	dev_info->hash_key_size = IGB_HKEY_MAX_INDEX * sizeof(uint32_t);

	dev_info->default_rxconf = (struct rte_eth_rxconf) {
		.rx_thresh = {
			.pthresh = IGB_DEFAULT_RX_PTHRESH,
			.hthresh = IGB_DEFAULT_RX_HTHRESH,
			.wthresh = IGB_DEFAULT_RX_WTHRESH,
		},
		.rx_free_thresh = IGB_DEFAULT_RX_FREE_THRESH,
		.rx_drop_en = 0,
		.offloads = 0,
	};

	dev_info->default_txconf = (struct rte_eth_txconf) {
		.tx_thresh = {
			.pthresh = IGB_DEFAULT_TX_PTHRESH,
			.hthresh = IGB_DEFAULT_TX_HTHRESH,
			.wthresh = IGB_DEFAULT_TX_WTHRESH,
		},
		.offloads = 0,
	};

	dev_info->rx_desc_lim = rx_desc_lim;
	dev_info->tx_desc_lim = tx_desc_lim;

	dev_info->speed_capa = ETH_LINK_SPEED_100G;

	dev_info->max_mtu = dev_info->max_rx_pktlen - MQNIC_ETH_OVERHEAD;
	dev_info->min_mtu = RTE_ETHER_MIN_MTU;

	return 0;
}

static const uint32_t *
eth_mqnic_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		/* refers to mqnic_rxd_pkt_info_to_pkt_type() */
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_TUNNEL_IP,
		RTE_PTYPE_INNER_L3_IPV6,
		RTE_PTYPE_INNER_L3_IPV6_EXT,
		RTE_PTYPE_INNER_L4_TCP,
		RTE_PTYPE_INNER_L4_UDP,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst == eth_mqnic_recv_pkts ||
	    dev->rx_pkt_burst == eth_mqnic_recv_scattered_pkts)
		return ptypes;
	return NULL;
}

/* return 0 means link status changed, -1 means not changed */
static int
eth_mqnic_link_update(struct rte_eth_dev *dev, int wait_to_complete)
{
	struct rte_eth_link link;

	RTE_SET_USED(wait_to_complete);

	memset(&link, 0, sizeof(link));

	/* Now we check if a transition has happened */
	link.link_duplex = ETH_LINK_FULL_DUPLEX;
	link.link_speed = ETH_SPEED_NUM_100G;
	link.link_status = ETH_LINK_UP;
	link.link_autoneg = 0;


	return rte_eth_linkstatus_set(dev, &link);
}

static int
eth_mqnic_promiscuous_enable(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static int
eth_mqnic_promiscuous_disable(struct rte_eth_dev *dev)
{
	RTE_SET_USED(dev);
	return 0;
}

static int
eth_mqnic_mtu_set(struct rte_eth_dev *dev, uint16_t mtu)
{
	mqnic_set_port_mtu(dev, mtu);
	return 0;
}

RTE_PMD_REGISTER_PCI(net_mqnic_igb, rte_mqnic_pmd);
RTE_PMD_REGISTER_PCI_TABLE(net_mqnic_igb, pci_id_mqnic_map);
RTE_PMD_REGISTER_KMOD_DEP(net_mqnic_igb, "uio_pci_generic");

/* see mqnic_logs.c */
RTE_INIT(mqnic_init_log)
{
	mqnic_mqnic_init_log();
}

