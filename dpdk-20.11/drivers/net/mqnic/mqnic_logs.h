/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2022 Bruce
 */

#ifndef _MQNIC_LOGS_H_
#define _MQNIC_LOGS_H_

#include <rte_log.h>

extern int mqnic_logtype_init;

#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, mqnic_logtype_init, \
		"%s(): " fmt "\n", __func__, ##args)

#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")

#ifdef RTE_LIBRTE_MQNIC_DEBUG_RX
extern int mqnic_logtype_rx;
#define PMD_RX_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, mqnic_logtype_rx,	\
		"%s(): " fmt "\n", __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_MQNIC_DEBUG_TX
extern int mqnic_logtype_tx;
#define PMD_TX_LOG(level, fmt, args...)			\
	rte_log(RTE_LOG_ ## level, mqnic_logtype_tx,	\
		"%s(): " fmt "\n", __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

void mqnic_mqnic_init_log(void);

#endif /* _MQNIC_LOGS_H_ */
