/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2001-2020 Intel Corporation
 */

#ifndef _MQNIC_HW_H_
#define _MQNIC_HW_H_

#include "mqnic_osdep.h"
#include "mqnic_regs.h"
#include "mqnic_defines.h"

struct mqnic_hw;

#define MQNIC_DEV_ID		0x1001

#define __le16 u16
#define __le32 u32
#define __le64 u64

/* Function pointers for the MAC. */
struct mqnic_mac_operations {
	s32  (*init_params)(struct mqnic_hw *);
	s32  (*id_led_init)(struct mqnic_hw *);
	s32  (*blink_led)(struct mqnic_hw *);
	bool (*check_mng_mode)(struct mqnic_hw *);
	s32  (*check_for_link)(struct mqnic_hw *);
	s32  (*cleanup_led)(struct mqnic_hw *);
	void (*clear_hw_cntrs)(struct mqnic_hw *);
	void (*clear_vfta)(struct mqnic_hw *);
	s32  (*get_bus_info)(struct mqnic_hw *);
	void (*set_lan_id)(struct mqnic_hw *);
	s32  (*get_link_up_info)(struct mqnic_hw *, u16 *, u16 *);
	s32  (*led_on)(struct mqnic_hw *);
	s32  (*led_off)(struct mqnic_hw *);
	void (*update_mc_addr_list)(struct mqnic_hw *, u8 *, u32);
	s32  (*reset_hw)(struct mqnic_hw *);
	s32  (*init_hw)(struct mqnic_hw *);
	void (*shutdown_serdes)(struct mqnic_hw *);
	void (*power_up_serdes)(struct mqnic_hw *);
	s32  (*setup_link)(struct mqnic_hw *);
	s32  (*setup_physical_interface)(struct mqnic_hw *);
	s32  (*setup_led)(struct mqnic_hw *);
	void (*write_vfta)(struct mqnic_hw *, u32, u32);
	void (*config_collision_dist)(struct mqnic_hw *);
	int  (*rar_set)(struct mqnic_hw *, u8*, u32);
	s32  (*read_mac_addr)(struct mqnic_hw *);
	s32  (*validate_mdi_setting)(struct mqnic_hw *);
	s32  (*acquire_swfw_sync)(struct mqnic_hw *, u16);
	void (*release_swfw_sync)(struct mqnic_hw *, u16);
};

struct mqnic_mac_info {
	struct mqnic_mac_operations ops;
	u8 addr[ETH_ADDR_LEN];
	u8 perm_addr[ETH_ADDR_LEN];

	//enum mqnic_mac_type type;

	u32 collision_delta;
	u32 ledctl_default;
	u32 ledctl_mode1;
	u32 ledctl_mode2;
	u32 mc_filter_type;
	u32 tx_packet_delta;
	u32 txcw;

	u16 current_ifs_val;
	u16 ifs_max_val;
	u16 ifs_min_val;
	u16 ifs_ratio;
	u16 ifs_step_size;
	u16 mta_reg_count;
	u16 uta_reg_count;

	/* Maximum size of the MTA register table in all supported adapters */
#define MAX_MTA_REG 128
	u32 mta_shadow[MAX_MTA_REG];
	u16 rar_entry_count;

	u8  forced_speed_duplex;

	bool adaptive_ifs;
	bool has_fwsm;
	bool arc_subsystem_valid;
	bool asf_firmware_present;
	bool autoneg;
	bool autoneg_failed;
	bool get_link_status;
	bool in_ifs_mode;
	bool report_tx_early;
	//enum mqnic_serdes_link_state serdes_link_state;
	bool serdes_has_link;
	bool tx_pkt_filtering;
};
struct mqnic_hw {
	void *back;

	//u8 *hw_addr;
	u8 *flash_address;
	unsigned long io_base;

	struct mqnic_mac_info  mac;

	u16 device_id;
	u16 subsystem_vendor_id;
	u16 subsystem_device_id;
	u16 vendor_id;

	u8  revision_id;

    //corundum add
	uint64_t hw_regs_size;
    phys_addr_t hw_regs_phys;
    u8 *hw_addr;
    u8 *phc_hw_addr;

    u8 base_mac[ETH_ALEN];

    u32 fw_id;
    u32 fw_ver;
    u32 board_id;
    u32 board_ver;

    u32 if_count;
    u32 if_stride;
    u32 if_csr_offset;
};

struct mqnic_desc {
    u16 rsvd0;
    u16 tx_csum_cmd;
    u32 len;
    u64 addr;
};

struct mqnic_cpl {
    u16 queue;
    u16 index;
    u16 len;
    u16 rsvd0;
    u32 ts_ns;
    u16 ts_s;
    u16 rx_csum;
    u32 rx_hash;
    u8 rx_hash_type;
    u8 rsvd1;
    u8 rsvd2;
    u8 rsvd3;
    u32 rsvd4;
    u32 rsvd5;
};

struct mqnic_event {
    u16 type;
    u16 source;
};

#endif
