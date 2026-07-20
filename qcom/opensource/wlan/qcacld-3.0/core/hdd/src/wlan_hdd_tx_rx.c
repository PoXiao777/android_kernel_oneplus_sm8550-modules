/*
 * Copyright (c) 2012-2021 The Linux Foundation. All rights reserved.
 * Copyright (c) 2021-2022 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for
 * any purpose with or without fee is hereby granted, provided that the
 * above copyright notice and this permission notice appear in all
 * copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 * WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 * DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 * PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 * TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/**
 * DOC: wlan_hdd_tx_rx.c
 *
 * Linux HDD Tx/RX APIs
 */

/* denote that this file does not allow legacy hddLog */
#define HDD_DISALLOW_LEGACY_HDDLOG 1
#include "osif_sync.h"
#include <wlan_hdd_tx_rx.h>
#include <wlan_hdd_softap_tx_rx.h>
#include <wlan_hdd_napi.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/etherdevice.h>
#include <linux/if_ether.h>
#include <linux/inetdevice.h>
#include <cds_sched.h>
#include <cds_utils.h>

#include <linux/wireless.h>
#include <net/cfg80211.h>
#include <net/ieee80211_radiotap.h>
#include "sap_api.h"
#include "wlan_hdd_wmm.h"
#include <cdp_txrx_cmn.h>
#include <cdp_txrx_peer_ops.h>
#include <cdp_txrx_flow_ctrl_v2.h>
#include <cdp_txrx_misc.h>
#include "wlan_hdd_power.h"
#include "wlan_hdd_cfg80211.h"
#include <wlan_hdd_tsf.h>
#include <net/tcp.h>

#include <ol_defines.h>
#include "cfg_ucfg_api.h"
#include "target_type.h"
#include "wlan_hdd_object_manager.h"
#include <wlan_hdd_sar_limits.h>
#include "wlan_hdd_object_manager.h"
#include "wlan_dp_ucfg_api.h"
#include "os_if_dp.h"
#include "wlan_ipa_ucfg_api.h"

#ifdef FEATURE_FRAME_INJECTION_SUPPORT
#include "wlan_hdd_frame_inject.h"
#endif

#ifdef TX_MULTIQ_PER_AC
#if defined(QCA_LL_TX_FLOW_CONTROL_V2) || defined(QCA_LL_PDEV_TX_FLOW_CONTROL)
/*
 * Mapping Linux AC interpretation to SME AC.
 * Host has 4 queues per access category (4 AC) and 1 high priority queue.
 * 16 flow-controlled queues for regular traffic and one non-flow
 * controlled queue for high priority control traffic(EOPOL, DHCP).
 * The seventeenth queue is mapped to AC_VO to allow for proper prioritization.
 */
const uint8_t hdd_qdisc_ac_to_tl_ac[] = {
	SME_AC_VO,
	SME_AC_VO,
	SME_AC_VO,
	SME_AC_VO,
	SME_AC_VI,
	SME_AC_VI,
	SME_AC_VI,
	SME_AC_VI,
	SME_AC_BE,
	SME_AC_BE,
	SME_AC_BE,
	SME_AC_BE,
	SME_AC_BK,
	SME_AC_BK,
	SME_AC_BK,
	SME_AC_BK,
	SME_AC_VO,
};

#else
const uint8_t hdd_qdisc_ac_to_tl_ac[] = {
	SME_AC_VO,
	SME_AC_VO,
	SME_AC_VO,
	SME_AC_VO,
	SME_AC_VI,
	SME_AC_VI,
	SME_AC_VI,
	SME_AC_VI,
	SME_AC_BE,
	SME_AC_BE,
	SME_AC_BE,
	SME_AC_BE,
	SME_AC_BK,
	SME_AC_BK,
	SME_AC_BK,
	SME_AC_BK,
};

#endif
#else
#if defined(QCA_LL_TX_FLOW_CONTROL_V2) || defined(QCA_LL_PDEV_TX_FLOW_CONTROL)
/*
 * Mapping Linux AC interpretation to SME AC.
 * Host has 5 tx queues, 4 flow-controlled queues for regular traffic and
 * one non-flow-controlled queue for high priority control traffic(EOPOL, DHCP).
 * The fifth queue is mapped to AC_VO to allow for proper prioritization.
 */
const uint8_t hdd_qdisc_ac_to_tl_ac[] = {
	SME_AC_VO,
	SME_AC_VI,
	SME_AC_BE,
	SME_AC_BK,
	SME_AC_VO,
};

#else
const uint8_t hdd_qdisc_ac_to_tl_ac[] = {
	SME_AC_VO,
	SME_AC_VI,
	SME_AC_BE,
	SME_AC_BK,
};

#endif
#endif

#ifdef QCA_HL_NETDEV_FLOW_CONTROL
void hdd_register_hl_netdev_fc_timer(struct hdd_adapter *adapter,
				     qdf_mc_timer_callback_t timer_callback)
{
	if (!adapter->tx_flow_timer_initialized) {
		qdf_mc_timer_init(&adapter->tx_flow_control_timer,
				  QDF_TIMER_TYPE_SW, timer_callback, adapter);
		adapter->tx_flow_timer_initialized = true;
	}
}

/**
 * hdd_deregister_hl_netdev_fc_timer() - Deregister HL Flow Control Timer
 * @adapter: adapter handle
 *
 * Return: none
 */
void hdd_deregister_hl_netdev_fc_timer(struct hdd_adapter *adapter)
{
	if (adapter->tx_flow_timer_initialized) {
		qdf_mc_timer_stop(&adapter->tx_flow_control_timer);
		qdf_mc_timer_destroy(&adapter->tx_flow_control_timer);
		adapter->tx_flow_timer_initialized = false;
	}
}

/**
 * hdd_tx_resume_timer_expired_handler() - TX Q resume timer handler
 * @adapter_context: pointer to vdev adapter
 *
 * Return: None
 */
void hdd_tx_resume_timer_expired_handler(void *adapter_context)
{
	struct hdd_adapter *adapter = (struct hdd_adapter *)adapter_context;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	u32 p_qpaused;
	u32 np_qpaused;

	if (!adapter) {
		hdd_err("invalid adapter context");
		return;
	}

	cdp_display_stats(soc, CDP_DUMP_TX_FLOW_POOL_INFO,
			  QDF_STATS_VERBOSITY_LEVEL_LOW);
	wlan_hdd_display_adapter_netif_queue_history(adapter);
	hdd_debug("Enabling queues");
	spin_lock_bh(&adapter->pause_map_lock);
	p_qpaused = adapter->pause_map & BIT(WLAN_DATA_FLOW_CONTROL_PRIORITY);
	np_qpaused = adapter->pause_map & BIT(WLAN_DATA_FLOW_CONTROL);
	spin_unlock_bh(&adapter->pause_map_lock);

	if (p_qpaused) {
		wlan_hdd_netif_queue_control(adapter,
					     WLAN_NETIF_PRIORITY_QUEUE_ON,
					     WLAN_DATA_FLOW_CONTROL_PRIORITY);
		cdp_hl_fc_set_os_queue_status(soc,
					      adapter->vdev_id,
					      WLAN_NETIF_PRIORITY_QUEUE_ON);
	}
	if (np_qpaused) {
		wlan_hdd_netif_queue_control(adapter,
					     WLAN_WAKE_NON_PRIORITY_QUEUE,
					     WLAN_DATA_FLOW_CONTROL);
		cdp_hl_fc_set_os_queue_status(soc,
					      adapter->vdev_id,
					      WLAN_WAKE_NON_PRIORITY_QUEUE);
	}
}

#endif /* QCA_HL_NETDEV_FLOW_CONTROL */

#ifdef QCA_LL_LEGACY_TX_FLOW_CONTROL
/**
 * hdd_tx_resume_timer_expired_handler() - TX Q resume timer handler
 * @adapter_context: pointer to vdev adapter
 *
 * If Blocked OS Q is not resumed during timeout period, to prevent
 * permanent stall, resume OS Q forcefully.
 *
 * Return: None
 */
void hdd_tx_resume_timer_expired_handler(void *adapter_context)
{
	struct hdd_adapter *adapter = (struct hdd_adapter *) adapter_context;

	if (!adapter) {
		/* INVALID ARG */
		return;
	}

	hdd_debug("Enabling queues");
	wlan_hdd_netif_queue_control(adapter, WLAN_WAKE_ALL_NETIF_QUEUE,
				     WLAN_CONTROL_PATH);
}

/**
 * hdd_tx_resume_false() - Resume OS TX Q false leads to queue disabling
 * @adapter: pointer to hdd adapter
 * @tx_resume: TX Q resume trigger
 *
 *
 * Return: None
 */
static void
hdd_tx_resume_false(struct hdd_adapter *adapter, bool tx_resume)
{
	if (true == tx_resume)
		return;

	/* Pause TX  */
	hdd_debug("Disabling queues");
	wlan_hdd_netif_queue_control(adapter, WLAN_STOP_ALL_NETIF_QUEUE,
				     WLAN_DATA_FLOW_CONTROL);

	if (QDF_TIMER_STATE_STOPPED ==
			qdf_mc_timer_get_current_state(&adapter->
						       tx_flow_control_timer)) {
		QDF_STATUS status;

		status = qdf_mc_timer_start(&adapter->tx_flow_control_timer,
				WLAN_HDD_TX_FLOW_CONTROL_OS_Q_BLOCK_TIME);

		if (!QDF_IS_STATUS_SUCCESS(status))
			hdd_err("Failed to start tx_flow_control_timer");
		else
			adapter->hdd_stats.tx_rx_stats.txflow_timer_cnt++;
	}

	adapter->hdd_stats.tx_rx_stats.txflow_pause_cnt++;
	adapter->hdd_stats.tx_rx_stats.is_txflow_paused = true;
}

/**
 * hdd_tx_resume_cb() - Resume OS TX Q.
 * @adapter_context: pointer to vdev apdapter
 * @tx_resume: TX Q resume trigger
 *
 * Q was stopped due to WLAN TX path low resource condition
 *
 * Return: None
 */
void hdd_tx_resume_cb(void *adapter_context, bool tx_resume)
{
	struct hdd_adapter *adapter = (struct hdd_adapter *) adapter_context;
	struct hdd_station_ctx *hdd_sta_ctx = NULL;

	if (!adapter) {
		/* INVALID ARG */
		return;
	}

	hdd_sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(adapter);

	/* Resume TX  */
	if (true == tx_resume) {
		if (QDF_TIMER_STATE_STOPPED !=
		    qdf_mc_timer_get_current_state(&adapter->
						   tx_flow_control_timer)) {
			qdf_mc_timer_stop(&adapter->tx_flow_control_timer);
		}
		hdd_debug("Enabling queues");
		wlan_hdd_netif_queue_control(adapter,
					     WLAN_WAKE_ALL_NETIF_QUEUE,
					     WLAN_DATA_FLOW_CONTROL);
		adapter->hdd_stats.tx_rx_stats.is_txflow_paused = false;
		adapter->hdd_stats.tx_rx_stats.txflow_unpause_cnt++;
	}
	hdd_tx_resume_false(adapter, tx_resume);
}

bool hdd_tx_flow_control_is_pause(void *adapter_context)
{
	struct hdd_adapter *adapter = (struct hdd_adapter *) adapter_context;

	if ((!adapter) || (WLAN_HDD_ADAPTER_MAGIC != adapter->magic)) {
		/* INVALID ARG */
		hdd_err("invalid adapter %pK", adapter);
		return false;
	}

	return adapter->pause_map & (1 << WLAN_DATA_FLOW_CONTROL);
}

void hdd_register_tx_flow_control(struct hdd_adapter *adapter,
		qdf_mc_timer_callback_t timer_callback,
		ol_txrx_tx_flow_control_fp flow_control_fp,
		ol_txrx_tx_flow_control_is_pause_fp flow_control_is_pause_fp)
{
	if (adapter->tx_flow_timer_initialized == false) {
		qdf_mc_timer_init(&adapter->tx_flow_control_timer,
			  QDF_TIMER_TYPE_SW,
			  timer_callback,
			  adapter);
		adapter->tx_flow_timer_initialized = true;
	}
	cdp_fc_register(cds_get_context(QDF_MODULE_ID_SOC),
		adapter->vdev_id, flow_control_fp, adapter,
		flow_control_is_pause_fp);
}

/**
 * hdd_deregister_tx_flow_control() - Deregister TX Flow control
 * @adapter: adapter handle
 *
 * Return: none
 */
void hdd_deregister_tx_flow_control(struct hdd_adapter *adapter)
{
	cdp_fc_deregister(cds_get_context(QDF_MODULE_ID_SOC),
			adapter->vdev_id);
	if (adapter->tx_flow_timer_initialized == true) {
		qdf_mc_timer_stop(&adapter->tx_flow_control_timer);
		qdf_mc_timer_destroy(&adapter->tx_flow_control_timer);
		adapter->tx_flow_timer_initialized = false;
	}
}

void hdd_get_tx_resource(uint8_t vdev_id,
			 struct qdf_mac_addr *mac_addr)
{
	struct hdd_adapter *adapter;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	uint16_t timer_value = WLAN_HDD_TX_FLOW_CONTROL_OS_Q_BLOCK_TIME;

	adapter = hdd_get_adapter_by_vdev(hdd_ctx, vdev_id);
	if (!adapter)
		return;

	if (adapter->device_mode == QDF_P2P_GO_MODE ||
	    adapter->device_mode == QDF_SAP_MODE)
		timer_value = WLAN_SAP_HDD_TX_FLOW_CONTROL_OS_Q_BLOCK_TIME;

	if (false ==
	    cdp_fc_get_tx_resource(cds_get_context(QDF_MODULE_ID_SOC),
				   OL_TXRX_PDEV_ID,
				   *mac_addr,
				   adapter->tx_flow_low_watermark,
				   adapter->tx_flow_hi_watermark_offset)) {
		hdd_debug("Disabling queues lwm %d hwm offset %d",
			 adapter->tx_flow_low_watermark,
			 adapter->tx_flow_hi_watermark_offset);
		wlan_hdd_netif_queue_control(adapter, WLAN_STOP_ALL_NETIF_QUEUE,
					     WLAN_DATA_FLOW_CONTROL);
		if ((adapter->tx_flow_timer_initialized == true) &&
		    (QDF_TIMER_STATE_STOPPED ==
		    qdf_mc_timer_get_current_state(&adapter->
						    tx_flow_control_timer))) {
			qdf_mc_timer_start(&adapter->tx_flow_control_timer,
					   timer_value);
			adapter->hdd_stats.tx_rx_stats.txflow_timer_cnt++;
			adapter->hdd_stats.tx_rx_stats.txflow_pause_cnt++;
			adapter->hdd_stats.tx_rx_stats.is_txflow_paused = true;
		}
	}
}


unsigned int
hdd_get_tx_flow_low_watermark(hdd_cb_handle cb_ctx, uint8_t intf_id)
{
	struct hdd_context *hdd_ctx = hdd_cb_handle_to_context(cb_ctx);
	struct hdd_adapter *adapter;

	adapter = hdd_get_adapter_by_vdev(hdd_ctx, intf_id);
	if (!adapter)
		return 0;

	return adapter->tx_flow_low_watermark;
}
#endif /* QCA_LL_LEGACY_TX_FLOW_CONTROL */

#ifdef FEATURE_FRAME_INJECTION_SUPPORT
#include <net/ieee80211_radiotap.h>

/*
 * Radiotap field bit positions (IEEE 802.11-2016 §9.14.3).
 * Only the fields relevant to TX injection are defined here.
 */
#define RADIOTAP_F_TSFT           0
#define RADIOTAP_F_FLAGS          1
#define RADIOTAP_F_RATE           2
#define RADIOTAP_F_CHANNEL        3
#define RADIOTAP_F_FHSS           4
#define RADIOTAP_F_DBM_ANTSIGNAL  5
#define RADIOTAP_F_DBM_ANTNOISE   6
#define RADIOTAP_F_LOCK_QUALITY   7
#define RADIOTAP_F_TX_ATTENUATION 8
#define RADIOTAP_F_DB_TX_ATTENUATION 9
#define RADIOTAP_F_DBM_TX_POWER  10
#define RADIOTAP_F_ANTENNA       11
#define RADIOTAP_F_DB_ANTSIGNAL  12
#define RADIOTAP_F_DB_ANTNOISE   13
#define RADIOTAP_F_RX_FLAGS      14
#define RADIOTAP_F_TX_FLAGS      15
#define RADIOTAP_F_RTS_RETRIES   16
#define RADIOTAP_F_DATA_RETRIES  17
#define RADIOTAP_F_XCHANNEL      18
#define RADIOTAP_F_MCS           19
#define RADIOTAP_F_AMPDU         20  /* A-MPDU Status (IEEE 802.11-2020 §9.14.3.8) */
#define RADIOTAP_F_VHT           21  /* VHT (IEEE 802.11-2020 §9.14.3.11) */
#define RADIOTAP_F_TIMESTAMP     22  /* Timestamp */
#define RADIOTAP_F_HE            23  /* 802.11ax HE (IEEE 802.11ax-2021 §9.14.3.14) */

/* Radiotap TX flags (field 15) */
#define RADIOTAP_F_TX_NOACK  0x0008
#define RADIOTAP_F_TX_NOSEQNO 0x0010

/* Radiotap FLAGS (field 1) bits */
#define RADIOTAP_F_WEP     0x04
#define RADIOTAP_F_FRAG    0x08

/* Radiotap MCS known bits (field 19, byte 0) */
#define RADIOTAP_MCS_HAVE_BW    0x01
#define RADIOTAP_MCS_HAVE_MCS   0x02
#define RADIOTAP_MCS_HAVE_GI    0x04
#define RADIOTAP_MCS_HAVE_FMT   0x08
#define RADIOTAP_MCS_HAVE_FEC   0x10
#define RADIOTAP_MCS_HAVE_STBC  0x20

/* Radiotap MCS flags (field 19, byte 1) */
#define RADIOTAP_MCS_BW_MASK    0x03
#define RADIOTAP_MCS_BW_20      0x00
#define RADIOTAP_MCS_BW_40      0x01
#define RADIOTAP_MCS_SGI        0x04
#define RADIOTAP_MCS_FMT_GF     0x08  /* Greenfield */
#define RADIOTAP_MCS_FEC_LDPC   0x10
#define RADIOTAP_MCS_STBC_MASK  0x60
#define RADIOTAP_MCS_STBC_SHIFT 5

/* Radiotap VHT known bits (field 21, bytes 0-1, u16 LE) */
#define RADIOTAP_VHT_KNOWN_STBC         BIT(0)
#define RADIOTAP_VHT_KNOWN_GI           BIT(2)
#define RADIOTAP_VHT_KNOWN_LDPC_OFDM    BIT(4)
#define RADIOTAP_VHT_KNOWN_BEAMFORMED   BIT(5)
#define RADIOTAP_VHT_KNOWN_BANDWIDTH    BIT(6)

/* Radiotap VHT flags byte (field 21, byte 2) */
#define RADIOTAP_VHT_FLAG_STBC          BIT(0)
#define RADIOTAP_VHT_FLAG_SGI           BIT(2)
#define RADIOTAP_VHT_FLAG_LDPC_OFDM     BIT(4)
#define RADIOTAP_VHT_FLAG_BEAMFORMED    BIT(5)

/*
 * VHT bandwidth field values (byte 3 of VHT radiotap field):
 *   0  = 20 MHz,  1-3  = 40 MHz variants,
 *   4-10 = 80 MHz variants, 11+ = 160 MHz variants.
 */
#define RADIOTAP_VHT_BW_20_THRESH    1   /* values < 1 → 20 MHz */
#define RADIOTAP_VHT_BW_80_THRESH    4   /* values 4-10 → 80 MHz */
#define RADIOTAP_VHT_BW_160_THRESH  11   /* values >= 11 → 160 MHz */

/* Radiotap HE known bits (field 23, data1 u16 LE) */
#define RADIOTAP_HE_DATA1_DATA_MCS_KNOWN    BIT(8)
#define RADIOTAP_HE_DATA1_CODING_KNOWN      BIT(10)
#define RADIOTAP_HE_DATA1_BW_RU_ALLOC_KNOWN BIT(15)

/* Radiotap HE data3 (field 23, bytes 4-5, u16 LE) */
#define RADIOTAP_HE_DATA3_DATA_MCS          0x000F
#define RADIOTAP_HE_DATA3_CODING            BIT(5)   /* 0=BCC, 1=LDPC */

/* Radiotap HE data5 (field 23, bytes 8-9, u16 LE) */
#define RADIOTAP_HE_DATA5_BW_RU_ALLOC_MASK 0x000F
#define RADIOTAP_HE_DATA5_GI_MASK          0x0060
#define RADIOTAP_HE_DATA5_GI_0_8_US        0x0000

/* Radiotap HE data6 (field 23, bytes 10-11, u16 LE) */
#define RADIOTAP_HE_DATA6_NSTS_MASK        0x000F

/*
 * Per-field {size, alignment} for radiotap fields 0..23.
 * Used to advance the pointer correctly when skipping fields.
 * IEEE 802.11-2020 §9.14.3 / radiotap.org field list.
 */
struct radiotap_field_info {
	uint8_t size;
	uint8_t align;
};

static const struct radiotap_field_info radiotap_fields[] = {
	[RADIOTAP_F_TSFT]              = { 8, 8 },  /* u64 */
	[RADIOTAP_F_FLAGS]             = { 1, 1 },  /* u8 */
	[RADIOTAP_F_RATE]              = { 1, 1 },  /* u8 */
	[RADIOTAP_F_CHANNEL]           = { 4, 2 },  /* u16 freq + u16 flags */
	[RADIOTAP_F_FHSS]              = { 2, 1 },  /* u8 hop_set + u8 hop_pattern */
	[RADIOTAP_F_DBM_ANTSIGNAL]     = { 1, 1 },  /* s8 */
	[RADIOTAP_F_DBM_ANTNOISE]      = { 1, 1 },  /* s8 */
	[RADIOTAP_F_LOCK_QUALITY]      = { 2, 2 },  /* u16 */
	[RADIOTAP_F_TX_ATTENUATION]    = { 2, 2 },  /* u16 */
	[RADIOTAP_F_DB_TX_ATTENUATION] = { 2, 2 },  /* u16 */
	[RADIOTAP_F_DBM_TX_POWER]      = { 1, 1 },  /* s8 */
	[RADIOTAP_F_ANTENNA]           = { 1, 1 },  /* u8 */
	[RADIOTAP_F_DB_ANTSIGNAL]      = { 1, 1 },  /* u8 */
	[RADIOTAP_F_DB_ANTNOISE]       = { 1, 1 },  /* u8 */
	[RADIOTAP_F_RX_FLAGS]          = { 2, 2 },  /* u16 */
	[RADIOTAP_F_TX_FLAGS]          = { 2, 2 },  /* u16 */
	[RADIOTAP_F_RTS_RETRIES]       = { 1, 1 },  /* u8 */
	[RADIOTAP_F_DATA_RETRIES]      = { 1, 1 },  /* u8 */
	[RADIOTAP_F_XCHANNEL]          = { 8, 4 },  /* u32 flags + u16 freq + u8 chan + u8 maxpower */
	[RADIOTAP_F_MCS]               = { 3, 1 },  /* u8 known + u8 flags + u8 mcs */
	[RADIOTAP_F_AMPDU]             = { 8, 4 },  /* u32 ref_num + u16 flags + u8 delimiter CRC + u8 reserved */
	[RADIOTAP_F_VHT]               = { 12, 2 }, /* u16 known + u8 flags + u8 bw + u8[4] mcs_nss + u8 coding + u8 group_id + u16 partial_aid */
	[RADIOTAP_F_TIMESTAMP]         = { 12, 8 }, /* u64 timestamp + u16 accuracy + u8 unit_samp + u8 flags */
	[RADIOTAP_F_HE]                = { 12, 2 }, /* 6×u16: data1..data6 */
};

#define RADIOTAP_FIELDS_MAX  ARRAY_SIZE(radiotap_fields)

/**
 * struct hdd_radiotap_tx_params - TX parameters extracted from radiotap header
 * @rate_100kbps: Legacy data rate in 100kbps units (0 = not specified)
 * @tx_flags: Mapped HDD injection TX flags
 * @channel_freq: Channel frequency in MHz (0 = not specified)
 * @mcs_index: 802.11n MCS index (0-76, valid only if has_mcs is true)
 * @mcs_bw: MCS bandwidth (0=20MHz, 1=40MHz)
 * @mcs_short_gi: Short guard interval requested
 * @mcs_greenfield: Greenfield preamble requested
 * @mcs_ldpc: LDPC FEC requested
 * @mcs_stbc: STBC streams (0=none)
 * @vht_mcs: 802.11ac VHT MCS index (0-9, valid only if has_vht is true)
 * @vht_nss: VHT spatial streams (1-8, valid only if has_vht is true)
 * @vht_bw: VHT BW encoding: 0=20, 1=40, 2=80, 3=160 MHz
 * @vht_short_gi: VHT short guard interval requested
 * @vht_ldpc: VHT LDPC FEC requested
 * @vht_stbc: VHT STBC streams (0=none)
 * @he_mcs: 802.11ax HE MCS index (0-11, valid only if has_he is true)
 * @he_nss: HE spatial streams (1-8, valid only if has_he is true)
 * @he_bw: HE BW encoding: 0=20, 1=40, 2=80, 3=160 MHz
 * @he_short_gi: HE short guard interval (0.8µs) requested
 * @he_ldpc: HE LDPC FEC requested
 * @has_rate: Whether legacy rate field was present
 * @has_channel: Whether channel field was present
 * @has_noack: Whether TX NO_ACK was requested
 * @has_mcs: Whether MCS field was present with valid index
 * @has_vht: Whether VHT field was present with valid MCS
 * @has_he: Whether HE field was present with valid MCS
 */
struct hdd_radiotap_tx_params {
	uint32_t rate_100kbps;
	uint32_t tx_flags;
	uint16_t channel_freq;
	uint8_t mcs_index;
	uint8_t mcs_bw;
	bool mcs_short_gi;
	bool mcs_greenfield;
	bool mcs_ldpc;
	uint8_t mcs_stbc;
	uint8_t vht_mcs;
	uint8_t vht_nss;
	uint8_t vht_bw;
	bool vht_short_gi;
	bool vht_ldpc;
	uint8_t vht_stbc;
	uint8_t he_mcs;
	uint8_t he_nss;
	uint8_t he_bw;
	bool he_short_gi;
	bool he_ldpc;
	bool has_rate;
	bool has_channel;
	bool has_noack;
	bool has_mcs;
	bool has_vht;
	bool has_he;
};

/**
 * hdd_parse_radiotap_tx_params() - Extract TX parameters from radiotap header
 * @data: Pointer to start of radiotap header
 * @len: Total length of radiotap + payload
 * @params: Output structure for extracted parameters
 *
 * Walks the radiotap it_present bitmask and extracts rate, channel,
 * TX flags, and MCS information for use in the frame injection request.
 * Handles all standard fields 0-19 for correct pointer advancement.
 *
 * Return: true on success, false if header is malformed
 */
static bool hdd_parse_radiotap_tx_params(const uint8_t *data, uint32_t len,
					 struct hdd_radiotap_tx_params *params)
{
	const struct ieee80211_radiotap_header *hdr;
	uint16_t rtap_len;
	uint32_t present;
	const uint8_t *ptr;
	const uint8_t *end;
	int bit;

	if (!data || !params || len < sizeof(*hdr))
		return false;

	memset(params, 0, sizeof(*params));

	hdr = (const struct ieee80211_radiotap_header *)data;
	if (hdr->it_version != 0)
		return false;

	rtap_len = get_unaligned_le16(&hdr->it_len);
	if (rtap_len < sizeof(*hdr) || rtap_len > len)
		return false;

	present = get_unaligned_le32(&hdr->it_present);
	end = data + rtap_len;

	/*
	 * Skip extended present bitmasks (bit 31 set = another u32 follows).
	 * Each extension is a 4-byte le32 immediately after the base header.
	 */
	{
		uint32_t p = present;
		const uint8_t *ext = (const uint8_t *)&hdr->it_present;

		while (p & BIT(31)) {
			ext += 4;
			if ((ext + 4) > end)
				return false;
			p = get_unaligned_le32(ext);
		}
		ptr = ext + 4;
	}

	/*
	 * Walk fields 0..RADIOTAP_F_HE.  For each present field, align
	 * the pointer, extract if it's a field we care about, then advance
	 * past it.
	 */
	for (bit = 0; bit <= RADIOTAP_F_HE && ptr < end; bit++) {
		const struct radiotap_field_info *fi;
		unsigned long off;

		if (!(present & BIT(bit)))
			continue;

		if (bit >= (int)RADIOTAP_FIELDS_MAX)
			break;

		fi = &radiotap_fields[bit];

		/* Align pointer for this field */
		if (fi->align > 1) {
			off = ptr - data;
			off = (off + fi->align - 1) & ~((unsigned long)fi->align - 1);
			ptr = data + off;
		}

		/* Bounds check before reading */
		if (ptr + fi->size > end)
			break;

		/* Extract fields we care about */
		switch (bit) {
		case RADIOTAP_F_RATE:
			/* Rate in 500kbps units → convert to 100kbps */
			params->rate_100kbps = (*ptr) * 5;
			params->has_rate = true;
			break;

		case RADIOTAP_F_CHANNEL:
			params->channel_freq = get_unaligned_le16(ptr);
			params->has_channel = true;
			break;

		case RADIOTAP_F_TX_FLAGS:
		{
			uint16_t txf = get_unaligned_le16(ptr);

			if (txf & RADIOTAP_F_TX_NOACK) {
				params->tx_flags |= HDD_FRAME_INJECT_TX_NO_ACK;
				params->has_noack = true;
			}
			break;
		}

		case RADIOTAP_F_MCS:
		{
			/*
			 * MCS field: 3 bytes
			 *   byte 0: known bitmask
			 *   byte 1: flags (BW, GI, format, FEC, STBC)
			 *   byte 2: MCS index (0-76)
			 */
			uint8_t known = ptr[0];
			uint8_t flags = ptr[1];
			uint8_t mcs = ptr[2];

			if (known & RADIOTAP_MCS_HAVE_MCS) {
				params->mcs_index = mcs;
				params->has_mcs = true;
			}
			if (known & RADIOTAP_MCS_HAVE_BW)
				params->mcs_bw = flags & RADIOTAP_MCS_BW_MASK;
			if (known & RADIOTAP_MCS_HAVE_GI)
				params->mcs_short_gi = !!(flags & RADIOTAP_MCS_SGI);
			if (known & RADIOTAP_MCS_HAVE_FMT)
				params->mcs_greenfield = !!(flags & RADIOTAP_MCS_FMT_GF);
			if (known & RADIOTAP_MCS_HAVE_FEC)
				params->mcs_ldpc = !!(flags & RADIOTAP_MCS_FEC_LDPC);
			if (known & RADIOTAP_MCS_HAVE_STBC)
				params->mcs_stbc = (flags & RADIOTAP_MCS_STBC_MASK)
						   >> RADIOTAP_MCS_STBC_SHIFT;
			break;
		}

		case RADIOTAP_F_VHT:
		{
			/*
			 * VHT field: 12 bytes (IEEE 802.11-2016 §9.14.3.11)
			 *   bytes [1:0]: known (u16 LE)
			 *   byte  [2]:   flags
			 *   byte  [3]:   bandwidth
			 *   bytes [7:4]: mcs_nss[4] — per-stream MCS/NSS
			 *                  bits[3:0] = MCS index (0-9)
			 *                  bits[7:4] = NSS-1 (0=1 stream)
			 *   byte  [8]:   coding (LDPC bitmask per stream)
			 *   byte  [9]:   group_id
			 *   bytes [11:10]: partial_aid (u16 LE)
			 */
			uint16_t known = get_unaligned_le16(ptr);
			uint8_t  flags = ptr[2];
			uint8_t  bw    = ptr[3];
			uint8_t  mcs_nss0 = ptr[4]; /* stream 0: MCS + NSS */
			uint8_t  coding   = ptr[8];
			uint8_t  vht_mcs  = mcs_nss0 & 0x0F;
			uint8_t  vht_nss  = ((mcs_nss0 >> 4) & 0x0F) + 1;

			/* Only extract if stream 0 has a valid MCS */
			if (vht_mcs <= 9 && vht_nss >= 1) {
				params->vht_mcs = vht_mcs;
				params->vht_nss = vht_nss;
				params->has_vht = true;
			}

			if (known & RADIOTAP_VHT_KNOWN_GI)
				params->vht_short_gi = !!(flags & RADIOTAP_VHT_FLAG_SGI);

			if (known & RADIOTAP_VHT_KNOWN_STBC)
				params->vht_stbc = !!(flags & RADIOTAP_VHT_FLAG_STBC);

			if (known & RADIOTAP_VHT_KNOWN_LDPC_OFDM)
				params->vht_ldpc = !!(coding & BIT(0));

			/*
			 * Map raw radiotap BW byte to our 2-bit BW encoding:
			 *   0=20MHz, 1=40MHz, 2=80MHz, 3=160MHz
			 */
			if (known & RADIOTAP_VHT_KNOWN_BANDWIDTH) {
				if (bw >= RADIOTAP_VHT_BW_160_THRESH)
					params->vht_bw = 3;
				else if (bw >= RADIOTAP_VHT_BW_80_THRESH)
					params->vht_bw = 2;
				else if (bw >= RADIOTAP_VHT_BW_20_THRESH)
					params->vht_bw = 1;
				else
					params->vht_bw = 0;
			}
			break;
		}

		case RADIOTAP_F_HE:
		{
			/*
			 * HE field: 12 bytes = 6×u16 (IEEE 802.11ax §9.14.3.14)
			 *   data1 [1:0]: known bits
			 *   data3 [5:4]: data MCS (bits[3:0]) + LDPC (bit[5])
			 *   data5 [9:8]: BW/RU alloc (bits[3:0]) + GI (bits[6:5])
			 *   data6 [11:10]: NSTS (bits[3:0])
			 */
			uint16_t data1 = get_unaligned_le16(ptr);
			uint16_t data3 = get_unaligned_le16(ptr + 4);
			uint16_t data5 = get_unaligned_le16(ptr + 8);
			uint16_t data6 = get_unaligned_le16(ptr + 10);
			uint8_t  bw_ru = data5 & RADIOTAP_HE_DATA5_BW_RU_ALLOC_MASK;
			uint8_t  he_mcs = data3 & RADIOTAP_HE_DATA3_DATA_MCS;
			uint8_t  he_nss = (data6 & RADIOTAP_HE_DATA6_NSTS_MASK);

			if (he_nss == 0)
				he_nss = 1;

			if (data1 & RADIOTAP_HE_DATA1_DATA_MCS_KNOWN) {
				params->he_mcs = he_mcs;
				params->he_nss = he_nss;
				params->has_he = true;
			}

			if (data1 & RADIOTAP_HE_DATA1_BW_RU_ALLOC_KNOWN)
				params->he_bw = (bw_ru >= 4) ? 0 : bw_ru;

			if (data1 & RADIOTAP_HE_DATA1_CODING_KNOWN)
				params->he_ldpc = !!(data3 & RADIOTAP_HE_DATA3_CODING);

			params->he_short_gi =
				((data5 & RADIOTAP_HE_DATA5_GI_MASK) ==
				 RADIOTAP_HE_DATA5_GI_0_8_US);
			break;
		}

		default:
			/* Field we don't need — just skip past it */
			break;
		}

		/* Advance pointer past this field */
		ptr += fi->size;
	}

	return true;
}

/**
 * hdd_is_monitor_tx_dev() - detect monitor-mode netdev tx context
 * @adapter: HDD adapter bound to @dev
 * @dev: Linux net device receiving tx frame
 *
 * Return: true if tx path should be treated as monitor injection
 */
static bool hdd_is_monitor_tx_dev(struct hdd_adapter *adapter,
				  struct net_device *dev)
{
	if (!adapter || !dev)
		return false;

	if (adapter->device_mode == QDF_MONITOR_MODE)
		return true;

	if (dev->type == ARPHRD_IEEE80211_RADIOTAP)
		return true;

	if (dev->ieee80211_ptr &&
	    dev->ieee80211_ptr->iftype == NL80211_IFTYPE_MONITOR)
		return true;

	return false;
}

/**
 * hdd_monitor_mode_tx_inject() - inject frame from monitor netdev
 * @adapter: HDD adapter
 * @dev: net_device carrying frame
 * @skb: Tx skb containing radiotap + 802.11, or raw 802.11 frame
 *
 * Return: None
 */
static void hdd_monitor_mode_tx_inject(struct hdd_adapter *adapter,
				       struct net_device *dev,
				       struct sk_buff *skb)
{
	static bool mon_tx_path_logged;
	static bool mon_ctx_force_logged;
	static bool mon_rtap_params_logged;
	struct ieee80211_radiotap_header *rthdr;
	struct hdd_radiotap_tx_params rtap_params;
	struct inject_frame_req *req;
	uint8_t *frame_data;
	uint16_t rtap_len;
	uint32_t frame_len;
	uint64_t now;
	QDF_STATUS status;
	bool has_radiotap = false;
	bool rtap_parsed = false;

	if (!adapter || !adapter->injection_ctx || !skb)
		goto drop;

	/*
	 * Monitor TX can be reached even when adapter->device_mode has not been
	 * switched to QDF_MONITOR_MODE. Keep injection context aligned with the
	 * actual netdev iftype seen on the TX path.
	 */
	if (!adapter->injection_ctx->is_monitor_mode) {
		adapter->injection_ctx->is_monitor_mode = true;
		if (!mon_ctx_force_logged) {
			hdd_warn("monitor tx: forcing injection monitor context on adapter vdev=%u iftype=%d",
				 adapter->vdev_id,
				 (dev && dev->ieee80211_ptr) ?
				 dev->ieee80211_ptr->iftype : -1);
			mon_ctx_force_logged = true;
		}
	}

	if (skb->len < 10) {
		hdd_err_rl("monitor tx: invalid skb len %u", skb->len);
		goto drop;
	}

	/*
	 * Prefer radiotap format (normal for monitor TX), but allow fallback to
	 * raw 802.11 if userspace or netdev path does not prepend radiotap.
	 */
	if (skb->len >= sizeof(struct ieee80211_radiotap_header)) {
		rthdr = (struct ieee80211_radiotap_header *)skb->data;
		if (rthdr->it_version == 0) {
			rtap_len = ieee80211_get_radiotap_len(skb->data);
			if (rtap_len >= sizeof(struct ieee80211_radiotap_header) && rtap_len < skb->len)
				has_radiotap = true;
		}
	}

	/*
	 * Extract TX parameters (rate, channel, flags) from the radiotap
	 * header before stripping it.  Tools like aireplay-ng, mdk4, and
	 * scapy encode desired TX rate and NO_ACK hints here.
	 */
	memset(&rtap_params, 0, sizeof(rtap_params));
	if (has_radiotap) {
		rtap_parsed = hdd_parse_radiotap_tx_params(skb->data,
							   skb->len,
							   &rtap_params);
		frame_data = skb->data + rtap_len;
		frame_len = skb->len - rtap_len;
	} else {
		frame_data = skb->data;
		frame_len = skb->len;
		hdd_warn_rl("monitor tx: no radiotap header (dev_type=%u), using raw 802.11 len=%u",
			    dev ? dev->type : 0, frame_len);
	}

	if (!frame_len || frame_len > HDD_FRAME_INJECT_MAX_SIZE) {
		hdd_err_rl("monitor tx: invalid 802.11 frame length %u", frame_len);
		goto drop;
	}

	if (!mon_tx_path_logged) {
		hdd_warn("monitor tx path active: mode=%d iftype=%d dev_type=%u radiotap=%u skb_len=%u frame_len=%u vdev=%u",
			 adapter->device_mode,
			 (dev && dev->ieee80211_ptr) ? dev->ieee80211_ptr->iftype : -1,
			 dev ? dev->type : 0, has_radiotap ? 1 : 0,
			 skb->len, frame_len, adapter->vdev_id);
		mon_tx_path_logged = true;
	}

	if (rtap_parsed && !mon_rtap_params_logged &&
	    (rtap_params.has_rate || rtap_params.has_noack ||
	     rtap_params.has_channel || rtap_params.has_mcs ||
	     rtap_params.has_vht || rtap_params.has_he)) {
		if (rtap_params.has_he)
			hdd_warn("monitor tx: radiotap HE params: mcs=%u nss=%u bw=%u sgi=%u ldpc=%u channel=%u MHz noack=%u",
				 rtap_params.he_mcs, rtap_params.he_nss,
				 rtap_params.he_bw,
				 rtap_params.he_short_gi ? 1 : 0,
				 rtap_params.he_ldpc ? 1 : 0,
				 rtap_params.channel_freq,
				 rtap_params.has_noack ? 1 : 0);
		else if (rtap_params.has_vht)
			hdd_warn("monitor tx: radiotap VHT params: mcs=%u nss=%u bw=%u sgi=%u ldpc=%u stbc=%u channel=%u MHz noack=%u",
				 rtap_params.vht_mcs, rtap_params.vht_nss,
				 rtap_params.vht_bw,
				 rtap_params.vht_short_gi ? 1 : 0,
				 rtap_params.vht_ldpc ? 1 : 0,
				 rtap_params.vht_stbc,
				 rtap_params.channel_freq,
				 rtap_params.has_noack ? 1 : 0);
		else
			hdd_warn("monitor tx: radiotap TX params: rate=%u (100kbps) mcs=%u (has=%u bw=%u sgi=%u) channel=%u MHz noack=%u flags=0x%x",
				 rtap_params.rate_100kbps,
				 rtap_params.mcs_index,
				 rtap_params.has_mcs ? 1 : 0,
				 rtap_params.mcs_bw,
				 rtap_params.mcs_short_gi ? 1 : 0,
				 rtap_params.channel_freq,
				 rtap_params.has_noack ? 1 : 0,
				 rtap_params.tx_flags);
		mon_rtap_params_logged = true;
	}

	req = qdf_mem_malloc(sizeof(*req));
	if (!req)
		goto drop;

	req->frame_data = qdf_mem_malloc(frame_len);
	if (!req->frame_data) {
		qdf_mem_free(req);
		goto drop;
	}

	qdf_mem_copy(req->frame_data, frame_data, frame_len);

	now = qdf_get_log_timestamp();

	req->frame_len = frame_len;
	req->retry_count = 0;
	req->timestamp = now;
	req->session_id = (uint32_t)now;
	req->submit_time = now;
	req->queue_time = 0;
	req->process_time = 0;
	req->complete_time = 0;

	/*
	 * Populate TX parameters from radiotap extraction.
	 * If no radiotap was present or parsing failed, these default to 0
	 * which lets the firmware choose its own defaults.
	 *
	 * MCS encoding in tx_rate:
	 *   If has_mcs is set, tx_rate is encoded as:
	 *     bits [7:0]   = MCS index (0-76)
	 *     bits [9:8]   = BW (0=20MHz, 1=40MHz)
	 *     bit  [10]    = Short GI
	 *     bit  [11]    = Greenfield
	 *     bit  [12]    = LDPC
	 *     bits [14:13] = STBC streams
	 *     bit  [15]    = MCS indicator flag (always 1 for MCS)
	 *   The WMA rate mapper checks bit 15 to distinguish MCS from legacy.
	 */
#define HDD_INJECT_RATE_MCS_FLAG    BIT(15)
#define HDD_INJECT_RATE_VHT_FLAG    BIT(16)  /* Set alongside MCS_FLAG for VHT */
#define HDD_INJECT_RATE_HE_FLAG     BIT(20)  /* Set alongside MCS_FLAG for HE (802.11ax) */
#define HDD_INJECT_RATE_MCS_MASK    0x007F   /* HT: MCS index 0-76; VHT/HE: bits[3:0] */
#define HDD_INJECT_RATE_BW_SHIFT    8        /* bits[9:8]: 0=20, 1=40, 2=80, 3=160 MHz */
#define HDD_INJECT_RATE_SGI_BIT     BIT(10)
#define HDD_INJECT_RATE_GF_BIT      BIT(11)  /* HT Greenfield (unused for VHT/HE) */
#define HDD_INJECT_RATE_LDPC_BIT    BIT(12)
#define HDD_INJECT_RATE_STBC_SHIFT  13       /* bits[14:13]: STBC streams */
#define HDD_INJECT_RATE_NSS_SHIFT   17       /* bits[19:17]: NSS-1 for VHT/HE */

	if (rtap_parsed) {
		req->tx_flags = rtap_params.tx_flags;
		if (rtap_params.has_he) {
			req->tx_rate = HDD_INJECT_RATE_MCS_FLAG |
				       HDD_INJECT_RATE_HE_FLAG |
				       (rtap_params.he_mcs & 0x0F) |
				       ((uint32_t)rtap_params.he_bw << HDD_INJECT_RATE_BW_SHIFT) |
				       (rtap_params.he_short_gi ? HDD_INJECT_RATE_SGI_BIT : 0) |
				       (rtap_params.he_ldpc ? HDD_INJECT_RATE_LDPC_BIT : 0) |
				       ((uint32_t)(rtap_params.he_nss - 1) << HDD_INJECT_RATE_NSS_SHIFT);
		} else if (rtap_params.has_vht) {
			/* Encode VHT params: MCS_FLAG + VHT_FLAG both set */
			req->tx_rate = HDD_INJECT_RATE_MCS_FLAG |
				       HDD_INJECT_RATE_VHT_FLAG |
				       (rtap_params.vht_mcs & 0x0F) |
				       ((uint32_t)rtap_params.vht_bw << HDD_INJECT_RATE_BW_SHIFT) |
				       (rtap_params.vht_short_gi ? HDD_INJECT_RATE_SGI_BIT : 0) |
				       (rtap_params.vht_ldpc ? HDD_INJECT_RATE_LDPC_BIT : 0) |
				       ((uint32_t)rtap_params.vht_stbc << HDD_INJECT_RATE_STBC_SHIFT) |
				       ((uint32_t)(rtap_params.vht_nss - 1) << HDD_INJECT_RATE_NSS_SHIFT);
		} else if (rtap_params.has_mcs) {
			/* Encode HT MCS params into tx_rate with flag bit */
			req->tx_rate = HDD_INJECT_RATE_MCS_FLAG |
				       (rtap_params.mcs_index & HDD_INJECT_RATE_MCS_MASK) |
				       ((uint32_t)rtap_params.mcs_bw << HDD_INJECT_RATE_BW_SHIFT) |
				       (rtap_params.mcs_short_gi ? HDD_INJECT_RATE_SGI_BIT : 0) |
				       (rtap_params.mcs_greenfield ? HDD_INJECT_RATE_GF_BIT : 0) |
				       (rtap_params.mcs_ldpc ? HDD_INJECT_RATE_LDPC_BIT : 0) |
				       ((uint32_t)rtap_params.mcs_stbc << HDD_INJECT_RATE_STBC_SHIFT);
		} else {
			req->tx_rate = rtap_params.rate_100kbps;
		}
	} else {
		req->tx_flags = 0;
		req->tx_rate = 0;
	}

	status = hdd_process_frame_injection(adapter, req);
	if (QDF_IS_STATUS_ERROR(status)) {
		hdd_err_rl("monitor tx: frame injection enqueue failed: %d", status);
		qdf_mem_free(req->frame_data);
		qdf_mem_free(req);
	}

drop:
	kfree_skb(skb);
}
#endif
#ifdef RECEIVE_OFFLOAD
qdf_napi_struct
*hdd_legacy_gro_get_napi(qdf_nbuf_t nbuf, bool enable_rxthread)
{
	struct qca_napi_info *qca_napii;
	struct qca_napi_data *napid;
	struct napi_struct *napi_to_use;

	napid = hdd_napi_get_all();
	if (unlikely(!napid))
		return NULL;

	qca_napii = hif_get_napi(QDF_NBUF_CB_RX_CTX_ID(nbuf), napid);
	if (unlikely(!qca_napii))
		return NULL;

	/*
	 * As we are breaking context in Rxthread mode, there is rx_thread NAPI
	 * corresponds each hif_napi.
	 */
	if (enable_rxthread)
		napi_to_use =  &qca_napii->rx_thread_napi;
	else
		napi_to_use = &qca_napii->napi;

	return (qdf_napi_struct *)napi_to_use;
}
#else
qdf_napi_struct
*hdd_legacy_gro_get_napi(qdf_nbuf_t nbuf, bool enable_rxthread)
{
	return NULL;
}
#endif

uint32_t hdd_txrx_get_tx_ack_count(struct hdd_adapter *adapter)
{
	return cdp_get_tx_ack_stats(cds_get_context(QDF_MODULE_ID_SOC),
				    adapter->vdev_id);
}

int hdd_set_udp_qos_upgrade_config(struct hdd_adapter *adapter,
				   uint8_t priority)
{
	if (adapter->device_mode != QDF_STA_MODE) {
		hdd_info_rl("Data priority upgrade only allowed in STA mode:%d",
			    adapter->device_mode);
		return -EINVAL;
	}

	if (priority >= QCA_WLAN_AC_ALL) {
		hdd_err_rl("Invalid data priority: %d", priority);
		return -EINVAL;
	}

	adapter->upgrade_udp_qos_threshold = priority;

	hdd_debug("UDP packets qos upgrade to: %d", priority);

	return 0;
}

#ifdef QCA_WIFI_FTM
static inline bool
hdd_drop_tx_packet_on_ftm(struct sk_buff *skb)
{
	if (hdd_get_conparam() == QDF_GLOBAL_FTM_MODE) {
		kfree_skb(skb);
		return true;
	}
	return false;
}
#else
static inline bool
hdd_drop_tx_packet_on_ftm(struct sk_buff *skb)
{
	return false;
}
#endif

/**
 * __hdd_hard_start_xmit() - Transmit a frame
 * @skb: pointer to OS packet (sk_buff)
 * @dev: pointer to network device
 *
 * Function registered with the Linux OS for transmitting
 * packets. This version of the function directly passes
 * the packet to Transport Layer.
 * In case of any packet drop or error, log the error with
 * INFO HIGH/LOW/MEDIUM to avoid excessive logging in kmsg.
 *
 * Return: None
 */
static void __hdd_hard_start_xmit(struct sk_buff *skb,
				  struct net_device *dev)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_tx_rx_stats *stats = &adapter->hdd_stats.tx_rx_stats;
	struct hdd_station_ctx *sta_ctx = &adapter->session.station;
	int cpu = qdf_get_smp_processor_id();
	bool granted;
	sme_ac_enum_type ac;
	enum sme_qos_wmmuptype up;
	QDF_STATUS status;

#ifdef FEATURE_FRAME_INJECTION_SUPPORT
	if (hdd_is_monitor_tx_dev(adapter, dev)) {
		hdd_monitor_mode_tx_inject(adapter, dev, skb);
		return;
	}
#endif

	if (hdd_drop_tx_packet_on_ftm(skb))
		return;

	osif_dp_mark_pkt_type(skb);

	/* Get TL AC corresponding to Qdisc queue index/AC. */
	ac = hdd_qdisc_ac_to_tl_ac[skb->queue_mapping];

	/*
	 * user priority from IP header, which is already extracted and set from
	 * select_queue call back function
	 */
	up = skb->priority;

	++stats->per_cpu[cpu].tx_classified_ac[ac];
#ifdef HDD_WMM_DEBUG
	QDF_TRACE(QDF_MODULE_ID_HDD_DATA, QDF_TRACE_LEVEL_DEBUG,
		  "%s: Classified as ac %d up %d", __func__, ac, up);
#endif /* HDD_WMM_DEBUG */

	if (HDD_PSB_CHANGED == adapter->psb_changed) {
		/*
		 * Function which will determine acquire admittance for a
		 * WMM AC is required or not based on psb configuration done
		 * in the framework
		 */
		hdd_wmm_acquire_access_required(adapter, ac);
	}
	/*
	 * Make sure we already have access to this access category
	 * or it is EAPOL or WAPI frame during initial authentication which
	 * can have artificially boosted higher qos priority.
	 */

	if (((adapter->psb_changed & (1 << ac)) &&
	     likely(adapter->hdd_wmm_status.ac_status[ac].
			is_access_allowed)) ||
	    ((!sta_ctx->conn_info.is_authenticated) &&
	     (QDF_NBUF_CB_PACKET_TYPE_EAPOL ==
	      QDF_NBUF_CB_GET_PACKET_TYPE(skb) ||
	      QDF_NBUF_CB_PACKET_TYPE_WAPI ==
	      QDF_NBUF_CB_GET_PACKET_TYPE(skb)))) {
		granted = true;
	} else {
		status = hdd_wmm_acquire_access(adapter, ac, &granted);
		adapter->psb_changed |= (1 << ac);
	}

	if (!granted) {
		bool is_default_ac = false;
		/*
		 * ADDTS request for this AC is sent, for now
		 * send this packet through next available lower
		 * Access category until ADDTS negotiation completes.
		 */
		while (!likely
			       (adapter->hdd_wmm_status.ac_status[ac].
			       is_access_allowed)) {
			switch (ac) {
			case SME_AC_VO:
				ac = SME_AC_VI;
				up = SME_QOS_WMM_UP_VI;
				break;
			case SME_AC_VI:
				ac = SME_AC_BE;
				up = SME_QOS_WMM_UP_BE;
				break;
			case SME_AC_BE:
				ac = SME_AC_BK;
				up = SME_QOS_WMM_UP_BK;
				break;
			default:
				ac = SME_AC_BK;
				up = SME_QOS_WMM_UP_BK;
				is_default_ac = true;
				break;
			}
			if (is_default_ac)
				break;
		}
		skb->priority = up;
		skb->queue_mapping = hdd_linux_up_to_ac_map[up];
	}

	/*
	 * adapter->vdev is directly dereferenced because this is per packet
	 * path, hdd_get_vdev_by_user() usage will be very costly as it
	 * involves lock access.
	 * Expectation here is vdev will be present during TX/RX processing
	 * and also DP internally maintaining vdev ref count
	 */
	status = ucfg_dp_start_xmit((qdf_nbuf_t)skb, adapter->vdev);
	if (QDF_IS_STATUS_SUCCESS(status)) {
		netif_trans_update(dev);
		wlan_hdd_sar_unsolicited_timer_start(adapter->hdd_ctx);
	} else {
		++stats->per_cpu[cpu].tx_dropped_ac[ac];
	}
}

/**
 * hdd_hard_start_xmit() - Wrapper function to protect
 * __hdd_hard_start_xmit from SSR
 * @skb: pointer to OS packet
 * @net_dev: pointer to net_device structure
 *
 * Function called by OS if any packet needs to transmit.
 *
 * Return: Always returns NETDEV_TX_OK
 */
netdev_tx_t hdd_hard_start_xmit(struct sk_buff *skb, struct net_device *net_dev)
{
	hdd_dp_ssr_protect();

	__hdd_hard_start_xmit(skb, net_dev);

	hdd_dp_ssr_unprotect();

	return NETDEV_TX_OK;
}

/**
 * __hdd_tx_timeout() - TX timeout handler
 * @dev: pointer to network device
 *
 * This function is registered as a netdev ndo_tx_timeout method, and
 * is invoked by the kernel if the driver takes too long to transmit a
 * frame.
 *
 * Return: None
 */
static void __hdd_tx_timeout(struct net_device *dev)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx;
	struct netdev_queue *txq;
	struct wlan_objmgr_vdev *vdev;
	int i = 0;

	hdd_ctx = WLAN_HDD_GET_CTX(adapter);

	if (hdd_ctx->hdd_wlan_suspended) {
		hdd_debug("Device is suspended, ignore WD timeout");
		return;
	}

	TX_TIMEOUT_TRACE(dev, QDF_MODULE_ID_HDD_DATA);
	DPTRACE(qdf_dp_trace(NULL, QDF_DP_TRACE_HDD_TX_TIMEOUT,
				QDF_TRACE_DEFAULT_PDEV_ID,
				NULL, 0, QDF_TX));

	/* Getting here implies we disabled the TX queues for too
	 * long. Queues are disabled either because of disassociation
	 * or low resource scenarios. In case of disassociation it is
	 * ok to ignore this. But if associated, we have do possible
	 * recovery here
	 */

	for (i = 0; i < NUM_TX_QUEUES; i++) {
		txq = netdev_get_tx_queue(dev, i);
		hdd_debug("Queue: %d status: %d txq->trans_start: %lu",
			  i, netif_tx_queue_stopped(txq), txq->trans_start);
	}

	hdd_debug("carrier state: %d", netif_carrier_ok(dev));

	wlan_hdd_display_adapter_netif_queue_history(adapter);

	vdev = hdd_objmgr_get_vdev_by_user(adapter, WLAN_DP_ID);
	if (vdev) {
		ucfg_dp_tx_timeout(vdev);
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_DP_ID);
	}
}

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0))
void hdd_tx_timeout(struct net_device *net_dev, unsigned int txqueue)
#else
void hdd_tx_timeout(struct net_device *net_dev)
#endif
{
	struct osif_vdev_sync *vdev_sync;

	if (osif_vdev_sync_op_start(net_dev, &vdev_sync))
		return;

	__hdd_tx_timeout(net_dev);

	osif_vdev_sync_op_stop(vdev_sync);
}

#ifdef RECEIVE_OFFLOAD
void hdd_disable_rx_ol_in_concurrency(bool disable)
{
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);

	if (!hdd_ctx)
		return;

	ucfg_dp_rx_handle_concurrency(hdd_ctx->psoc, disable);
}
#else /* RECEIVE_OFFLOAD */
void hdd_disable_rx_ol_in_concurrency(bool disable)
{
}
#endif /* RECEIVE_OFFLOAD */

#ifdef WLAN_FEATURE_TSF_PLUS_SOCK_TS
void hdd_tsf_timestamp_rx(hdd_cb_handle ctx, qdf_nbuf_t netbuf)
{
	struct hdd_context *hdd_ctx = hdd_cb_handle_to_context(ctx);

	if (!hdd_tsf_is_rx_set(hdd_ctx))
		return;

	hdd_rx_timestamp(netbuf, ktime_to_us(netbuf->tstamp));
}

void hdd_get_tsf_time_cb(uint8_t vdev_id, uint64_t input_time,
			 uint64_t *tsf_time)
{
	struct hdd_adapter *adapter;
	struct hdd_context *hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);

	adapter = hdd_get_adapter_by_vdev(hdd_ctx, vdev_id);
	if (!adapter)
		return;

	hdd_get_tsf_time(adapter, input_time, tsf_time);
}
#endif

/**
 * hdd_reason_type_to_string() - return string conversion of reason type
 * @reason: reason type
 *
 * This utility function helps log string conversion of reason type.
 *
 * Return: string conversion of device mode, if match found;
 *        "Unknown" otherwise.
 */
const char *hdd_reason_type_to_string(enum netif_reason_type reason)
{
	switch (reason) {
	CASE_RETURN_STRING(WLAN_CONTROL_PATH);
	CASE_RETURN_STRING(WLAN_DATA_FLOW_CONTROL);
	CASE_RETURN_STRING(WLAN_FW_PAUSE);
	CASE_RETURN_STRING(WLAN_TX_ABORT);
	CASE_RETURN_STRING(WLAN_VDEV_STOP);
	CASE_RETURN_STRING(WLAN_PEER_UNAUTHORISED);
	CASE_RETURN_STRING(WLAN_THERMAL_MITIGATION);
	CASE_RETURN_STRING(WLAN_DATA_FLOW_CONTROL_PRIORITY);
	default:
		return "Invalid";
	}
}

/**
 * hdd_action_type_to_string() - return string conversion of action type
 * @action: action type
 *
 * This utility function helps log string conversion of action_type.
 *
 * Return: string conversion of device mode, if match found;
 *        "Unknown" otherwise.
 */
const char *hdd_action_type_to_string(enum netif_action_type action)
{

	switch (action) {
	CASE_RETURN_STRING(WLAN_STOP_ALL_NETIF_QUEUE);
	CASE_RETURN_STRING(WLAN_START_ALL_NETIF_QUEUE);
	CASE_RETURN_STRING(WLAN_WAKE_ALL_NETIF_QUEUE);
	CASE_RETURN_STRING(WLAN_STOP_ALL_NETIF_QUEUE_N_CARRIER);
	CASE_RETURN_STRING(WLAN_START_ALL_NETIF_QUEUE_N_CARRIER);
	CASE_RETURN_STRING(WLAN_NETIF_TX_DISABLE);
	CASE_RETURN_STRING(WLAN_NETIF_TX_DISABLE_N_CARRIER);
	CASE_RETURN_STRING(WLAN_NETIF_CARRIER_ON);
	CASE_RETURN_STRING(WLAN_NETIF_CARRIER_OFF);
	CASE_RETURN_STRING(WLAN_NETIF_PRIORITY_QUEUE_ON);
	CASE_RETURN_STRING(WLAN_NETIF_PRIORITY_QUEUE_OFF);
	CASE_RETURN_STRING(WLAN_NETIF_VO_QUEUE_ON);
	CASE_RETURN_STRING(WLAN_NETIF_VO_QUEUE_OFF);
	CASE_RETURN_STRING(WLAN_NETIF_VI_QUEUE_ON);
	CASE_RETURN_STRING(WLAN_NETIF_VI_QUEUE_OFF);
	CASE_RETURN_STRING(WLAN_NETIF_BE_BK_QUEUE_ON);
	CASE_RETURN_STRING(WLAN_NETIF_BE_BK_QUEUE_OFF);
	CASE_RETURN_STRING(WLAN_WAKE_NON_PRIORITY_QUEUE);
	CASE_RETURN_STRING(WLAN_STOP_NON_PRIORITY_QUEUE);
	default:
		return "Invalid";
	}
}

/**
 * wlan_hdd_update_queue_oper_stats - update queue operation statistics
 * @adapter: adapter handle
 * @action: action type
 * @reason: reason type
 */
static void wlan_hdd_update_queue_oper_stats(struct hdd_adapter *adapter,
	enum netif_action_type action, enum netif_reason_type reason)
{
	switch (action) {
	case WLAN_STOP_ALL_NETIF_QUEUE:
	case WLAN_STOP_ALL_NETIF_QUEUE_N_CARRIER:
	case WLAN_NETIF_BE_BK_QUEUE_OFF:
	case WLAN_NETIF_VI_QUEUE_OFF:
	case WLAN_NETIF_VO_QUEUE_OFF:
	case WLAN_NETIF_PRIORITY_QUEUE_OFF:
	case WLAN_STOP_NON_PRIORITY_QUEUE:
		adapter->queue_oper_stats[reason].pause_count++;
		break;
	case WLAN_START_ALL_NETIF_QUEUE:
	case WLAN_WAKE_ALL_NETIF_QUEUE:
	case WLAN_START_ALL_NETIF_QUEUE_N_CARRIER:
	case WLAN_NETIF_BE_BK_QUEUE_ON:
	case WLAN_NETIF_VI_QUEUE_ON:
	case WLAN_NETIF_VO_QUEUE_ON:
	case WLAN_NETIF_PRIORITY_QUEUE_ON:
	case WLAN_WAKE_NON_PRIORITY_QUEUE:
		adapter->queue_oper_stats[reason].unpause_count++;
		break;
	default:
		break;
	}
}

/**
 * hdd_netdev_queue_is_locked()
 * @txq: net device tx queue
 *
 * For SMP system, always return false and we could safely rely on
 * __netif_tx_trylock().
 *
 * Return: true locked; false not locked
 */
#ifdef QCA_CONFIG_SMP
static inline bool hdd_netdev_queue_is_locked(struct netdev_queue *txq)
{
	return false;
}
#else
static inline bool hdd_netdev_queue_is_locked(struct netdev_queue *txq)
{
	return txq->xmit_lock_owner != -1;
}
#endif

/**
 * wlan_hdd_update_txq_timestamp() - update txq timestamp
 * @dev: net device
 *
 * Return: none
 */
static void wlan_hdd_update_txq_timestamp(struct net_device *dev)
{
	struct netdev_queue *txq;
	int i;

	for (i = 0; i < NUM_TX_QUEUES; i++) {
		txq = netdev_get_tx_queue(dev, i);

		/*
		 * On UP system, kernel will trigger watchdog bite if spinlock
		 * recursion is detected. Unfortunately recursion is possible
		 * when it is called in dev_queue_xmit() context, where stack
		 * grabs the lock before calling driver's ndo_start_xmit
		 * callback.
		 */
		if (!hdd_netdev_queue_is_locked(txq)) {
			if (__netif_tx_trylock(txq)) {
				txq_trans_update(txq);
				__netif_tx_unlock(txq);
			}
		}
	}
}

/**
 * wlan_hdd_update_unpause_time() - update unpause time
 * @adapter: adapter handle
 *
 * Return: none
 */
static void wlan_hdd_update_unpause_time(struct hdd_adapter *adapter)
{
	qdf_time_t curr_time = qdf_system_ticks();

	adapter->total_unpause_time += curr_time - adapter->last_time;
	adapter->last_time = curr_time;
}

/**
 * wlan_hdd_update_pause_time() - update pause time
 * @adapter: adapter handle
 * @temp_map: pause map
 *
 * Return: none
 */
static void wlan_hdd_update_pause_time(struct hdd_adapter *adapter,
				       uint32_t temp_map)
{
	qdf_time_t curr_time = qdf_system_ticks();
	uint8_t i;
	qdf_time_t pause_time;

	pause_time = curr_time - adapter->last_time;
	adapter->total_pause_time += pause_time;
	adapter->last_time = curr_time;

	for (i = 0; i < WLAN_REASON_TYPE_MAX; i++) {
		if (temp_map & (1 << i)) {
			adapter->queue_oper_stats[i].total_pause_time +=
								 pause_time;
			break;
		}
	}

}

uint32_t
wlan_hdd_dump_queue_history_state(struct hdd_netif_queue_history *queue_history,
				  char *buf, uint32_t size)
{
	unsigned int i;
	unsigned int index = 0;

	for (i = 0; i < NUM_TX_QUEUES; i++) {
		index += qdf_scnprintf(buf + index,
				       size - index,
				       "%u:0x%lx ",
				       i, queue_history->tx_q_state[i]);
	}

	return index;
}

/**
 * wlan_hdd_update_queue_history_state() - Save a copy of dev TX queues state
 * @dev: interface netdev
 * @q_hist: adapter queue history
 *
 * Save netdev TX queues state into adapter queue history.
 *
 * Return: None
 */
static void
wlan_hdd_update_queue_history_state(struct net_device *dev,
				    struct hdd_netif_queue_history *q_hist)
{
	unsigned int i = 0;
	uint32_t num_tx_queues = 0;
	struct netdev_queue *txq = NULL;

	num_tx_queues = qdf_min(dev->num_tx_queues, (uint32_t)NUM_TX_QUEUES);

	for (i = 0; i < num_tx_queues; i++) {
		txq = netdev_get_tx_queue(dev, i);
		q_hist->tx_q_state[i] = txq->state;
	}
}

/**
 * wlan_hdd_stop_non_priority_queue() - stop non priority queues
 * @adapter: adapter handle
 *
 * Return: None
 */
static inline void wlan_hdd_stop_non_priority_queue(struct hdd_adapter *adapter)
{
	uint8_t i;

	for (i = 0; i < TX_QUEUES_PER_AC; i++) {
		netif_stop_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_VO, i));
		netif_stop_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_VI, i));
		netif_stop_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_BE, i));
		netif_stop_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_BK, i));
	}
}

/**
 * wlan_hdd_wake_non_priority_queue() - wake non priority queues
 * @adapter: adapter handle
 *
 * Return: None
 */
static inline void wlan_hdd_wake_non_priority_queue(struct hdd_adapter *adapter)
{
	uint8_t i;

	for (i = 0; i < TX_QUEUES_PER_AC; i++) {
		netif_wake_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_VO, i));
		netif_wake_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_VI, i));
		netif_wake_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_BE, i));
		netif_wake_subqueue(adapter->dev,
				    TX_GET_QUEUE_IDX(HDD_LINUX_AC_BK, i));
	}
}

static inline
void hdd_wake_queues_for_ac(struct net_device *dev, enum hdd_wmm_linuxac ac)
{
	uint8_t i;

	for (i = 0; i < TX_QUEUES_PER_AC; i++)
		netif_wake_subqueue(dev, TX_GET_QUEUE_IDX(ac, i));
}

static inline
void hdd_stop_queues_for_ac(struct net_device *dev, enum hdd_wmm_linuxac ac)
{
	uint8_t i;

	for (i = 0; i < TX_QUEUES_PER_AC; i++)
		netif_stop_subqueue(dev, TX_GET_QUEUE_IDX(ac, i));
}

/**
 * wlan_hdd_netif_queue_control() - Use for netif_queue related actions
 * @adapter: adapter handle
 * @action: action type
 * @reason: reason type
 *
 * This is single function which is used for netif_queue related
 * actions like start/stop of network queues and on/off carrier
 * option.
 *
 * Return: None
 */
void wlan_hdd_netif_queue_control(struct hdd_adapter *adapter,
	enum netif_action_type action, enum netif_reason_type reason)
{
	uint32_t temp_map;
	uint8_t index;
	struct hdd_netif_queue_history *txq_hist_ptr;

	if ((!adapter) || (WLAN_HDD_ADAPTER_MAGIC != adapter->magic) ||
	    (!adapter->dev)) {
		hdd_err("adapter is invalid");
		return;
	}

	if (hdd_adapter_is_link_adapter(adapter))
		return;

	switch (action) {

	case WLAN_NETIF_CARRIER_ON:
		netif_carrier_on(adapter->dev);
		break;

	case WLAN_NETIF_CARRIER_OFF:
		netif_carrier_off(adapter->dev);
		break;

	case WLAN_STOP_ALL_NETIF_QUEUE:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			netif_tx_stop_all_queues(adapter->dev);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		adapter->pause_map |= (1 << reason);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_STOP_NON_PRIORITY_QUEUE:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			wlan_hdd_stop_non_priority_queue(adapter);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		adapter->pause_map |= (1 << reason);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_PRIORITY_QUEUE_ON:
		spin_lock_bh(&adapter->pause_map_lock);
		if (reason == WLAN_DATA_FLOW_CTRL_PRI) {
			temp_map = adapter->subqueue_pause_map;
			adapter->subqueue_pause_map &= ~(1 << reason);
		} else {
			temp_map = adapter->pause_map;
			adapter->pause_map &= ~(1 << reason);
		}
		if (!adapter->pause_map) {
			netif_wake_subqueue(adapter->dev,
				HDD_LINUX_AC_HI_PRIO * TX_QUEUES_PER_AC);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_PRIORITY_QUEUE_OFF:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			netif_stop_subqueue(adapter->dev,
				    HDD_LINUX_AC_HI_PRIO * TX_QUEUES_PER_AC);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		if (reason == WLAN_DATA_FLOW_CTRL_PRI)
			adapter->subqueue_pause_map |= (1 << reason);
		else
			adapter->pause_map |= (1 << reason);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_BE_BK_QUEUE_OFF:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			hdd_stop_queues_for_ac(adapter->dev, HDD_LINUX_AC_BK);
			hdd_stop_queues_for_ac(adapter->dev, HDD_LINUX_AC_BE);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		adapter->subqueue_pause_map |= (1 << reason);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_BE_BK_QUEUE_ON:
		spin_lock_bh(&adapter->pause_map_lock);
		temp_map = adapter->subqueue_pause_map;
		adapter->subqueue_pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			hdd_wake_queues_for_ac(adapter->dev, HDD_LINUX_AC_BK);
			hdd_wake_queues_for_ac(adapter->dev, HDD_LINUX_AC_BE);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_VI_QUEUE_OFF:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			hdd_stop_queues_for_ac(adapter->dev, HDD_LINUX_AC_VI);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		adapter->subqueue_pause_map |= (1 << reason);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_VI_QUEUE_ON:
		spin_lock_bh(&adapter->pause_map_lock);
		temp_map = adapter->subqueue_pause_map;
		adapter->subqueue_pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			hdd_wake_queues_for_ac(adapter->dev, HDD_LINUX_AC_VI);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_VO_QUEUE_OFF:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			hdd_stop_queues_for_ac(adapter->dev, HDD_LINUX_AC_VO);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		adapter->subqueue_pause_map |= (1 << reason);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_VO_QUEUE_ON:
		spin_lock_bh(&adapter->pause_map_lock);
		temp_map = adapter->subqueue_pause_map;
		adapter->subqueue_pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			hdd_wake_queues_for_ac(adapter->dev, HDD_LINUX_AC_VO);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_START_ALL_NETIF_QUEUE:
		spin_lock_bh(&adapter->pause_map_lock);
		temp_map = adapter->pause_map;
		adapter->pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			netif_tx_start_all_queues(adapter->dev);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_WAKE_ALL_NETIF_QUEUE:
		spin_lock_bh(&adapter->pause_map_lock);
		temp_map = adapter->pause_map;
		adapter->pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			netif_tx_wake_all_queues(adapter->dev);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_WAKE_NON_PRIORITY_QUEUE:
		spin_lock_bh(&adapter->pause_map_lock);
		temp_map = adapter->pause_map;
		adapter->pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			wlan_hdd_wake_non_priority_queue(adapter);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_STOP_ALL_NETIF_QUEUE_N_CARRIER:
		spin_lock_bh(&adapter->pause_map_lock);
		if (!adapter->pause_map) {
			netif_tx_stop_all_queues(adapter->dev);
			wlan_hdd_update_txq_timestamp(adapter->dev);
			wlan_hdd_update_unpause_time(adapter);
		}
		adapter->pause_map |= (1 << reason);
		netif_carrier_off(adapter->dev);
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_START_ALL_NETIF_QUEUE_N_CARRIER:
		spin_lock_bh(&adapter->pause_map_lock);
		netif_carrier_on(adapter->dev);
		temp_map = adapter->pause_map;
		adapter->pause_map &= ~(1 << reason);
		if (!adapter->pause_map) {
			netif_tx_start_all_queues(adapter->dev);
			wlan_hdd_update_pause_time(adapter, temp_map);
		}
		spin_unlock_bh(&adapter->pause_map_lock);
		break;

	case WLAN_NETIF_ACTION_TYPE_NONE:
		break;

	default:
		hdd_err("unsupported action %d", action);
	}

	spin_lock_bh(&adapter->pause_map_lock);
	if (adapter->pause_map & (1 << WLAN_PEER_UNAUTHORISED))
		wlan_hdd_process_peer_unauthorised_pause(adapter);

	index = adapter->history_index++;
	if (adapter->history_index == WLAN_HDD_MAX_HISTORY_ENTRY)
		adapter->history_index = 0;
	spin_unlock_bh(&adapter->pause_map_lock);

	wlan_hdd_update_queue_oper_stats(adapter, action, reason);

	adapter->queue_oper_history[index].time = qdf_system_ticks();
	adapter->queue_oper_history[index].netif_action = action;
	adapter->queue_oper_history[index].netif_reason = reason;
	if (reason >= WLAN_DATA_FLOW_CTRL_BE_BK)
		adapter->queue_oper_history[index].pause_map =
			adapter->subqueue_pause_map;
	else
		adapter->queue_oper_history[index].pause_map =
			adapter->pause_map;

	txq_hist_ptr = &adapter->queue_oper_history[index];

	wlan_hdd_update_queue_history_state(adapter->dev, txq_hist_ptr);
}

void hdd_print_netdev_txq_status(struct net_device *dev)
{
	unsigned int i;

	if (!dev)
		return;

	for (i = 0; i < dev->num_tx_queues; i++) {
		struct netdev_queue *txq = netdev_get_tx_queue(dev, i);

			hdd_debug("netdev tx queue[%u] state:0x%lx",
				  i, txq->state);
	}
}

#ifdef FEATURE_MONITOR_MODE_SUPPORT
/**
 * hdd_set_mon_rx_cb() - Set Monitor mode Rx callback
 * @dev:        Pointer to net_device structure
 *
 * Return: 0 for success; non-zero for failure
 */
int hdd_set_mon_rx_cb(struct net_device *dev)
{
	struct hdd_adapter *adapter = WLAN_HDD_GET_PRIV_PTR(dev);
	struct hdd_context *hdd_ctx =  WLAN_HDD_GET_CTX(adapter);
	int ret;
	QDF_STATUS qdf_status;
	struct ol_txrx_desc_type sta_desc = {0};
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);
	struct wlan_objmgr_vdev *vdev;

	WLAN_ADDR_COPY(sta_desc.peer_addr.bytes, adapter->mac_addr.bytes);

	vdev = hdd_objmgr_get_vdev_by_user(adapter, WLAN_DP_ID);
	if (!vdev) {
		hdd_err("failed to get vdev");
		return -EINVAL;
	}

	qdf_status = ucfg_dp_mon_register_txrx_ops(vdev);
	if (QDF_STATUS_SUCCESS != qdf_status) {
		hdd_err("failed to register txrx ops. Status= %d [0x%08X]",
			qdf_status, qdf_status);
		hdd_objmgr_put_vdev_by_user(vdev, WLAN_DP_ID);
		goto exit;
	}
	hdd_objmgr_put_vdev_by_user(vdev, WLAN_DP_ID);

	qdf_status = sme_create_mon_session(hdd_ctx->mac_handle,
					    adapter->mac_addr.bytes,
					    adapter->vdev_id);
	if (QDF_STATUS_SUCCESS != qdf_status) {
		hdd_err("sme_create_mon_session() failed to register. Status= %d [0x%08X]",
			qdf_status, qdf_status);
	}

	/* peer is created wma_vdev_attach->wma_create_peer */
	qdf_status = cdp_peer_register(soc, OL_TXRX_PDEV_ID, &sta_desc);
	if (QDF_STATUS_SUCCESS != qdf_status) {
		hdd_err("cdp_peer_register() failed to register. Status= %d [0x%08X]",
			qdf_status, qdf_status);
		goto exit;
	}

exit:
	ret = qdf_status_to_os_return(qdf_status);
	return ret;
}
#endif

void hdd_tx_queue_cb(hdd_handle_t hdd_handle, uint32_t vdev_id,
		     enum netif_action_type action,
		     enum netif_reason_type reason)
{
	struct hdd_context *hdd_ctx = hdd_handle_to_context(hdd_handle);
	struct hdd_adapter *adapter;

	/*
	 * Validating the context is not required here.
	 * if there is a driver unload/SSR in progress happening in a
	 * different context and it has been scheduled to run and
	 * driver got a firmware event of sta kick out, then it is
	 * good to disable the Tx Queue to stop the influx of traffic.
	 */
	if (!hdd_ctx) {
		hdd_err("Invalid context passed");
		return;
	}

	adapter = hdd_get_adapter_by_vdev(hdd_ctx, vdev_id);
	if (!adapter) {
		hdd_err("vdev_id %d does not exist with host", vdev_id);
		return;
	}
	hdd_debug("Tx Queue action %d on vdev %d", action, vdev_id);

	wlan_hdd_netif_queue_control(adapter, action, reason);
}

#ifdef QCA_LL_LEGACY_TX_FLOW_CONTROL
/**
 * hdd_ini_tx_flow_control() - Initialize INIs concerned about tx flow control
 * @config: pointer to hdd config
 * @psoc: pointer to psoc obj
 *
 * Return: none
 */
static void hdd_ini_tx_flow_control(struct hdd_config *config,
				    struct wlan_objmgr_psoc *psoc)
{
	config->tx_flow_low_watermark =
		cfg_get(psoc, CFG_DP_LL_TX_FLOW_LWM);
	config->tx_flow_hi_watermark_offset =
		cfg_get(psoc, CFG_DP_LL_TX_FLOW_HWM_OFFSET);
	config->tx_flow_max_queue_depth =
		cfg_get(psoc, CFG_DP_LL_TX_FLOW_MAX_Q_DEPTH);
	config->tx_lbw_flow_low_watermark =
		cfg_get(psoc, CFG_DP_LL_TX_LBW_FLOW_LWM);
	config->tx_lbw_flow_hi_watermark_offset =
		cfg_get(psoc, CFG_DP_LL_TX_LBW_FLOW_HWM_OFFSET);
	config->tx_lbw_flow_max_queue_depth =
		cfg_get(psoc, CFG_DP_LL_TX_LBW_FLOW_MAX_Q_DEPTH);
	config->tx_hbw_flow_low_watermark =
		cfg_get(psoc, CFG_DP_LL_TX_HBW_FLOW_LWM);
	config->tx_hbw_flow_hi_watermark_offset =
		cfg_get(psoc, CFG_DP_LL_TX_HBW_FLOW_HWM_OFFSET);
	config->tx_hbw_flow_max_queue_depth =
		cfg_get(psoc, CFG_DP_LL_TX_HBW_FLOW_MAX_Q_DEPTH);
}
#else
static void hdd_ini_tx_flow_control(struct hdd_config *config,
				    struct wlan_objmgr_psoc *psoc)
{
}
#endif

#ifdef WLAN_FEATURE_MSCS
/**
 * hdd_ini_mscs_params() - Initialize INIs related to MSCS feature
 * @config: pointer to hdd config
 * @psoc: pointer to psoc obj
 *
 * Return: none
 */
static void hdd_ini_mscs_params(struct hdd_config *config,
				struct wlan_objmgr_psoc *psoc)
{
	config->mscs_pkt_threshold =
		cfg_get(psoc, CFG_VO_PKT_COUNT_THRESHOLD);
	config->mscs_voice_interval =
		cfg_get(psoc, CFG_MSCS_VOICE_INTERVAL);
}

#else
static inline void hdd_ini_mscs_params(struct hdd_config *config,
				       struct wlan_objmgr_psoc *psoc)
{
}
#endif

void hdd_dp_cfg_update(struct wlan_objmgr_psoc *psoc,
		       struct hdd_context *hdd_ctx)
{
	struct hdd_config *config;

	config = hdd_ctx->config;

	config->napi_cpu_affinity_mask =
		cfg_get(psoc, CFG_DP_NAPI_CE_CPU_MASK);
	config->enable_fisa_lru_deletion =
				cfg_get(psoc, CFG_DP_RX_FISA_LRU_DEL_ENABLE);
	config->cfg_wmi_credit_cnt = cfg_get(psoc, CFG_DP_HTC_WMI_CREDIT_CNT);

	hdd_ini_tx_flow_control(config, psoc);
	hdd_ini_mscs_params(config, psoc);
}

#ifdef QCA_LL_LEGACY_TX_FLOW_CONTROL
/**
 * hdd_set_tx_flow_info() - To set TX flow info
 * @adapter: pointer to adapter
 * @pre_adp_ctx: pointer to pre-adapter
 * @target_channel: target channel
 * @pre_adp_channel: pre-adapter channel
 * @dbgid: Debug IDs
 *
 * This routine is called to set TX flow info
 *
 * Return: None
 */
static void hdd_set_tx_flow_info(struct hdd_adapter *adapter,
				 struct hdd_adapter **pre_adp_ctx,
				 uint8_t target_channel,
				 uint8_t *pre_adp_channel,
				 wlan_net_dev_ref_dbgid dbgid)
{
	struct hdd_context *hdd_ctx;
	uint8_t channel24;
	uint8_t channel5;
	struct hdd_adapter *adapter2_4 = NULL;
	struct hdd_adapter *adapter5 = NULL;
	void *soc = cds_get_context(QDF_MODULE_ID_SOC);

	hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	if (!hdd_ctx)
		return;

	if (!target_channel)
		return;

	/*
	 * This is first adapter detected as active
	 * set as default for none concurrency case
	 */
	if (!(*pre_adp_channel)) {
		/* If IPA UC data path is enabled,
		 * target should reserve extra tx descriptors
		 * for IPA data path.
		 * Then host data path should allow less TX
		 * packet pumping in case IPA
		 * data path enabled
		 */
		if (ucfg_ipa_uc_is_enabled() &&
		    adapter->device_mode == QDF_SAP_MODE) {
			adapter->tx_flow_low_watermark =
				hdd_ctx->config->tx_flow_low_watermark +
				WLAN_TFC_IPAUC_TX_DESC_RESERVE;
		} else {
			adapter->tx_flow_low_watermark =
				hdd_ctx->config->tx_flow_low_watermark;
		}
		adapter->tx_flow_hi_watermark_offset =
			hdd_ctx->config->tx_flow_hi_watermark_offset;
		cdp_fc_ll_set_tx_pause_q_depth(soc,
				adapter->vdev_id,
				hdd_ctx->config->tx_flow_max_queue_depth);
		hdd_debug("MODE %d,CH %d,LWM %d,HWM %d,TXQDEP %d",
			  adapter->device_mode,
			  target_channel,
			  adapter->tx_flow_low_watermark,
			  adapter->tx_flow_low_watermark +
			  adapter->tx_flow_hi_watermark_offset,
			  hdd_ctx->config->tx_flow_max_queue_depth);
		*pre_adp_channel = target_channel;
		*pre_adp_ctx = adapter;
	} else {
		/*
		 * SCC, disable TX flow control for both
		 * SCC each adapter cannot reserve dedicated
		 * channel resource, as a result, if any adapter
		 * blocked OS Q by flow control,
		 * blocked adapter will lost chance to recover
		 */
		if (*pre_adp_channel == target_channel) {
			/* Current adapter */
			adapter->tx_flow_low_watermark = 0;
			adapter->tx_flow_hi_watermark_offset = 0;
			cdp_fc_ll_set_tx_pause_q_depth(soc,
				adapter->vdev_id,
				hdd_ctx->config->tx_hbw_flow_max_queue_depth);
			hdd_debug("SCC: MODE %s(%d), CH %d, LWM %d, HWM %d, TXQDEP %d",
			          qdf_opmode_str(adapter->device_mode),
			          adapter->device_mode,
			          target_channel,
			          adapter->tx_flow_low_watermark,
			          adapter->tx_flow_low_watermark +
			          adapter->tx_flow_hi_watermark_offset,
			          hdd_ctx->config->tx_hbw_flow_max_queue_depth);

			if (!(*pre_adp_ctx)) {
				hdd_err("SCC: Previous adapter context NULL");
				hdd_adapter_dev_put_debug(adapter, dbgid);
				return;
			}

			/* Previous adapter */
			(*pre_adp_ctx)->tx_flow_low_watermark = 0;
			(*pre_adp_ctx)->tx_flow_hi_watermark_offset = 0;
			cdp_fc_ll_set_tx_pause_q_depth(soc,
				(*pre_adp_ctx)->vdev_id,
				hdd_ctx->config->tx_hbw_flow_max_queue_depth);
			hdd_debug("SCC: MODE %s(%d), CH %d, LWM %d, HWM %d, TXQDEP %d",
				  qdf_opmode_str((*pre_adp_ctx)->device_mode),
				  (*pre_adp_ctx)->device_mode,
				  target_channel,
				  (*pre_adp_ctx)->tx_flow_low_watermark,
				  (*pre_adp_ctx)->tx_flow_low_watermark +
				  (*pre_adp_ctx)->tx_flow_hi_watermark_offset,
				 hdd_ctx->config->tx_hbw_flow_max_queue_depth);
		} else {
			/*
			 * MCC, each adapter will have dedicated
			 * resource
			 */
			/* current channel is 2.4 */
			if (target_channel <=
			    WLAN_HDD_TX_FLOW_CONTROL_MAX_24BAND_CH) {
				channel24 = target_channel;
				channel5 = *pre_adp_channel;
				adapter2_4 = adapter;
				adapter5 = *pre_adp_ctx;
			} else {
				/* Current channel is 5 */
				channel24 = *pre_adp_channel;
				channel5 = target_channel;
				adapter2_4 = *pre_adp_ctx;
				adapter5 = adapter;
			}

			if (!adapter5) {
				hdd_err("MCC: 5GHz adapter context NULL");
				hdd_adapter_dev_put_debug(adapter, dbgid);
				return;
			}
			adapter5->tx_flow_low_watermark =
				hdd_ctx->config->tx_hbw_flow_low_watermark;
			adapter5->tx_flow_hi_watermark_offset =
				hdd_ctx->config->tx_hbw_flow_hi_watermark_offset;
			cdp_fc_ll_set_tx_pause_q_depth(soc,
				adapter5->vdev_id,
				hdd_ctx->config->tx_hbw_flow_max_queue_depth);
			hdd_debug("MCC: MODE %s(%d), CH %d, LWM %d, HWM %d, TXQDEP %d",
				  qdf_opmode_str(adapter5->device_mode),
				  adapter5->device_mode,
				  channel5,
				  adapter5->tx_flow_low_watermark,
				  adapter5->tx_flow_low_watermark +
				  adapter5->tx_flow_hi_watermark_offset,
				  hdd_ctx->config->tx_hbw_flow_max_queue_depth);

			if (!adapter2_4) {
				hdd_err("MCC: 2.4GHz adapter context NULL");
				hdd_adapter_dev_put_debug(adapter, dbgid);
				return;
			}
			adapter2_4->tx_flow_low_watermark =
				hdd_ctx->config->tx_lbw_flow_low_watermark;
			adapter2_4->tx_flow_hi_watermark_offset =
				hdd_ctx->config->tx_lbw_flow_hi_watermark_offset;
			cdp_fc_ll_set_tx_pause_q_depth(soc,
				adapter2_4->vdev_id,
				hdd_ctx->config->tx_lbw_flow_max_queue_depth);
			hdd_debug("MCC: MODE %s(%d), CH %d, LWM %d, HWM %d, TXQDEP %d",
				  qdf_opmode_str(adapter2_4->device_mode),
				  adapter2_4->device_mode,
				  channel24,
				  adapter2_4->tx_flow_low_watermark,
				  adapter2_4->tx_flow_low_watermark +
				  adapter2_4->tx_flow_hi_watermark_offset,
				  hdd_ctx->config->tx_lbw_flow_max_queue_depth);
		}
	}
}

void wlan_hdd_set_tx_flow_info(void)
{
	struct hdd_adapter *adapter, *next_adapter = NULL;
	struct hdd_station_ctx *sta_ctx;
	struct hdd_ap_ctx *hdd_ap_ctx;
	struct hdd_hostapd_state *hostapd_state;
	uint8_t sta_channel = 0, p2p_channel = 0, ap_channel = 0;
	struct hdd_context *hdd_ctx;
	uint8_t target_channel = 0;
	uint8_t pre_adp_channel = 0;
	struct hdd_adapter *pre_adp_ctx = NULL;
	wlan_net_dev_ref_dbgid dbgid = NET_DEV_HOLD_IPA_SET_TX_FLOW_INFO;

	hdd_ctx = cds_get_context(QDF_MODULE_ID_HDD);
	if (!hdd_ctx)
		return;

	hdd_for_each_adapter_dev_held_safe(hdd_ctx, adapter, next_adapter,
					   dbgid) {
		switch (adapter->device_mode) {
		case QDF_STA_MODE:
			sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(adapter);
			if (hdd_cm_is_vdev_associated(adapter)) {
				sta_channel = wlan_reg_freq_to_chan(
						hdd_ctx->pdev,
						sta_ctx->conn_info.chan_freq);
				target_channel = sta_channel;
			}
			break;
		case QDF_P2P_CLIENT_MODE:
			sta_ctx = WLAN_HDD_GET_STATION_CTX_PTR(adapter);
			if (hdd_cm_is_vdev_associated(adapter)) {
				p2p_channel = wlan_reg_freq_to_chan(
					hdd_ctx->pdev,
					sta_ctx->conn_info.chan_freq);
				target_channel = p2p_channel;
			}
			break;
		case QDF_P2P_GO_MODE:
			hdd_ap_ctx = WLAN_HDD_GET_AP_CTX_PTR(adapter);
			hostapd_state = WLAN_HDD_GET_HOSTAP_STATE_PTR(adapter);
			if (hostapd_state->bss_state == BSS_START &&
			    hostapd_state->qdf_status ==
			    QDF_STATUS_SUCCESS) {
				p2p_channel = wlan_reg_freq_to_chan(
					hdd_ctx->pdev,
					hdd_ap_ctx->operating_chan_freq);
				target_channel = p2p_channel;
			}
			break;
		case QDF_SAP_MODE:
			hdd_ap_ctx = WLAN_HDD_GET_AP_CTX_PTR(adapter);
			hostapd_state = WLAN_HDD_GET_HOSTAP_STATE_PTR(adapter);
			if (hostapd_state->bss_state == BSS_START &&
			    hostapd_state->qdf_status ==
			    QDF_STATUS_SUCCESS) {
				ap_channel = wlan_reg_freq_to_chan(
					hdd_ctx->pdev,
					hdd_ap_ctx->operating_chan_freq);
				target_channel = ap_channel;
			}
			break;
		default:
			break;
		}

		hdd_set_tx_flow_info(adapter,
				     &pre_adp_ctx,
				     target_channel,
				     &pre_adp_channel,
				     dbgid);
		target_channel = 0;

		hdd_adapter_dev_put_debug(adapter, dbgid);
	}
}
#endif /* QCA_LL_LEGACY_TX_FLOW_CONTROL */
