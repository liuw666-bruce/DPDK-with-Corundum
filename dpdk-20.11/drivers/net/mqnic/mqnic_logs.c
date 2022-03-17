/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include "mqnic_logs.h"

/* declared as extern in mqnic_logs.h */
int mqnic_logtype_init;
int mqnic_logtype_driver;

#ifdef RTE_LIBRTE_MQNIC_DEBUG_RX
int mqnic_logtype_rx;
#endif
#ifdef RTE_LIBRTE_MQNIC_DEBUG_TX
int mqnic_logtype_tx;
#endif
#ifdef RTE_LIBRTE_MQNIC_DEBUG_TX_FREE
int mqnic_logtype_tx_free;
#endif

/* avoids double registering of logs if EM and IGB drivers are in use */
static int mqnic_log_initialized;

void
mqnic_mqnic_init_log(void)
{
	if (mqnic_log_initialized)
		return;

	mqnic_logtype_init = rte_log_register("pmd.net.mqnic.init");
	if (mqnic_logtype_init >= 0)
		rte_log_set_level(mqnic_logtype_init, RTE_LOG_NOTICE);
	mqnic_logtype_driver = rte_log_register("pmd.net.mqnic.driver");
	if (mqnic_logtype_driver >= 0)
		rte_log_set_level(mqnic_logtype_driver, RTE_LOG_NOTICE);

#ifdef RTE_LIBRTE_MQNIC_DEBUG_RX
	mqnic_logtype_rx = rte_log_register("pmd.net.mqnic.rx");
	if (mqnic_logtype_rx >= 0)
		rte_log_set_level(mqnic_logtype_rx, RTE_LOG_NOTICE);
#endif

#ifdef RTE_LIBRTE_MQNIC_DEBUG_TX
	mqnic_logtype_tx = rte_log_register("pmd.net.mqnic.tx");
	if (mqnic_logtype_tx >= 0)
		rte_log_set_level(mqnic_logtype_tx, RTE_LOG_NOTICE);
#endif

#ifdef RTE_LIBRTE_MQNIC_DEBUG_TX_FREE
	mqnic_logtype_tx_free = rte_log_register("pmd.net.mqnic.tx_free");
	if (mqnic_logtype_tx_free >= 0)
		rte_log_set_level(mqnic_logtype_tx_free, RTE_LOG_NOTICE);
#endif

	mqnic_log_initialized = 1;
}
