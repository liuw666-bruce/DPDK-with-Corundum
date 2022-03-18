/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Bruce
 */

#include "mqnic_logs.h"

/* declared as extern in mqnic_logs.h */
int mqnic_logtype_init;

#ifdef RTE_LIBRTE_MQNIC_DEBUG_RX
int mqnic_logtype_rx;
#endif
#ifdef RTE_LIBRTE_MQNIC_DEBUG_TX
int mqnic_logtype_tx;
#endif

static int mqnic_log_initialized;

void
mqnic_mqnic_init_log(void)
{
	if (mqnic_log_initialized)
		return;

	mqnic_logtype_init = rte_log_register("pmd.net.mqnic.init");
	if (mqnic_logtype_init >= 0)
		rte_log_set_level(mqnic_logtype_init, RTE_LOG_NOTICE);

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

	mqnic_log_initialized = 1;
}
