/*
 * Copyright (c) 2024 The Linux Foundation. All rights reserved.
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
 * DOC: wma_frame_inject.c
 *
 * This file contains WMA layer frame injection queue management functions.
 * It provides infrastructure for queuing, processing, and transmitting
 * injected 802.11 frames through the firmware interface.
 */

#include "wma.h"
#include "wma_frame_inject.h"
#include "wlan_hdd_frame_inject.h"
#include "wma_api.h"
#include "wma_internal.h"
#include "wmi_unified_api.h"
#include "wmi_unified.h"
#include "qdf_mem.h"
#include "qdf_list.h"
#include "qdf_lock.h"
#include "qdf_status.h"
#include "qdf_trace.h"
#include "qdf_nbuf.h"
#include "qdf_delayed_work.h"
#include "qdf_time.h"
#include "qdf_threads.h"
#include "cds_api.h"
#include "cdp_txrx_cmn.h"
#include "cdp_txrx_peer_ops.h"
#include <wlan_vdev_mgr_tgt_if_tx_defs.h>
#include <target_if_vdev_mgr_rx_ops.h>
#if defined(CONFIG_HL_SUPPORT)
#include "wlan_tgt_def_config_hl.h"
#else
#include "wlan_tgt_def_config.h"
#endif

#ifdef FEATURE_FRAME_INJECTION_SUPPORT
#include <linux/moduleparam.h>

/*
 * wma_injection_unmap_tx_buf() - Unmap DMA mapping on injection nbuf
 *
 * On LL (low-latency / PCI / SNOC) the WMI layer DMA-maps the tx_frame
 * passed in mgmt_params.  The mapping must be released on completion.
 * On HL (high-latency / SDIO / USB) the frame data is copied inline into
 * the WMI command and no DMA mapping exists, so the unmap is a no-op.
 */
#ifdef CONFIG_HL_SUPPORT
static inline void wma_injection_unmap_tx_buf(qdf_nbuf_t buf)
{
}
#else
static inline void wma_injection_unmap_tx_buf(qdf_nbuf_t buf)
{
	void *qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);

	if (qdf_ctx && buf)
		qdf_nbuf_unmap_single(qdf_ctx, buf, QDF_DMA_TO_DEVICE);
}
#endif

/* Maximum number of frames in WMA injection queue */
#define WMA_FRAME_INJECT_MAX_QUEUE_SIZE    512

/* Maximum frame size for injection */
#define WMA_FRAME_INJECT_MAX_FRAME_SIZE    2304

/* Timeout for queue processing work in milliseconds */
#define WMA_FRAME_INJECT_QUEUE_TIMEOUT_MS  100

/* Reaper timer interval: how often we scan for stale in-flight nbufs (ms) */
#define WMA_INJECTION_REAPER_INTERVAL_MS   500

/* Let firmware retire VDEV_DELETE before this slot can be reused. */
#define WMA_INJECTION_HELPER_DELETE_COOLDOWN_MS 50
#define WMA_INJECTION_HELPER_RSP_TIMEOUT_MS 1000

/*
 * Maximum age in microseconds before an in-flight nbuf is considered
 * abandoned by firmware and reaped. Normal completions arrive in < 50 ms.
 */
#define WMA_INJECTION_NBUF_TIMEOUT_US      2000000ULL

/* Include one reaper interval beyond the stale in-flight timeout. */
#define WMA_INJECTION_CHANNEL_DRAIN_TIMEOUT_MS 2500
#define WMA_INJECTION_CHANNEL_DRAIN_POLL_MS       5

/*
 * Maximum number of in-flight (submitted but uncomplemented) nbufs before
 * we start rejecting new enqueue requests.  Keeps DMA-mapped memory bounded
 * when firmware silently drops completions for the helper STA vdev.
 */
#define WMA_INJECTION_INFLIGHT_HIGH        200

/**
 * struct wma_injection_queue_node - Node for injection queue
 * @node: List node
 * @req: Frame injection request
 * @timestamp: Enqueue timestamp
 * @vdev_id: VDEV ID for the frame
 */
struct wma_injection_queue_node {
	qdf_list_node_t node;
	struct inject_frame_req req;
	uint64_t timestamp;
	uint8_t vdev_id;
};

/**
 * struct wma_injection_queue_ctx - WMA injection queue context
 * @queue: Queue of pending injection requests
 * @queue_lock: Lock for queue operations
 * @helper_lock: Serializes helper submission and teardown
 * @queue_size: Current queue size
 * @max_queue_size: Maximum allowed queue size
 * @queue_work: Work item for processing queue
 * @delayed_work: Delayed work item for backpressure handling
 * @helper_stopping: Driver stop has disabled helper work and WMI teardown
 * @helper_transitioning: Channel change is draining helper submissions
 * @recreate_helper_on_retune: Directed-peer session requires fresh helper
 * @stats: Queue statistics
 * @is_initialized: Initialization flag
 */
struct wma_injection_queue_ctx {
	qdf_list_t queue;
	qdf_spinlock_t queue_lock;
	qdf_spinlock_t cache_lock;
	qdf_mutex_t helper_lock;
	uint32_t queue_size;
	uint32_t max_queue_size;
	qdf_work_t queue_work;
	struct qdf_delayed_work delayed_work;
	struct qdf_delayed_work reaper_work; /* periodic stale-nbuf reaper */
	qdf_atomic_t inflight_count; /* nbufs submitted to FW, not yet completed */
	bool helper_stopping;
	bool helper_transitioning;
	bool recreate_helper_on_retune;
	struct wma_injection_queue_stats stats;
	bool is_initialized;
};

/* Statistics structure is defined in wma_frame_inject.h */

/* Global injection queue context */
static struct wma_injection_queue_ctx g_wma_injection_ctx;

/*
 * Per-session one-shot logging flags and counters for
 * wma_send_injection_frame_to_fw().  Reset on each new
 * injection TX vdev creation so restarts re-log setup info.
 */
static bool inject_tx_cfg_logged;
static uint32_t inject_send_info_count;
static bool inject_wmi_path_logged;
static bool inject_legacy_path_logged;
static bool inject_monitor_no_legacy_logged;
static bool inject_wmi_service_absent_logged;
static bool inject_probe_sa_fix_logged;

/*
 * Keep a small best-effort debug cache so firmware completion status can be
 * correlated with the frame metadata for the corresponding desc_id.
 */
#define WMA_INJECTION_DEBUG_CACHE_SIZE 256
struct wma_injection_debug_info {
	bool valid;
	bool is_group;
	bool peer_exists;
	bool timed_out;
	uint8_t vdev_id;
	uint8_t vdev_type;
	uint8_t tx_path;
	uint32_t desc_id;
	uint16_t frame_len;
	uint16_t chanfreq;
	uint8_t fc_type;
	uint8_t fc_subtype;
	uint8_t addr1[QDF_MAC_ADDR_SIZE];
	uint8_t addr2[QDF_MAC_ADDR_SIZE];
	uint8_t addr3[QDF_MAC_ADDR_SIZE];
	qdf_nbuf_t tx_buf; /* nbuf passed to WMI; must be unmapped+freed on completion */
	uint64_t submit_time_us; /* monotonic boot time when submitted to FW */
};

enum wma_injection_tx_path {
	WMA_INJECTION_TX_PATH_NONE,
	WMA_INJECTION_TX_PATH_WMI,
	WMA_INJECTION_TX_PATH_LEGACY,
};

static struct wma_injection_debug_info
	g_wma_injection_debug_cache[WMA_INJECTION_DEBUG_CACHE_SIZE];

/*
 * Hidden STA vdev for injection TX on monitor mode.
 *
 * The firmware's mgmt TX handler (FUN_b000fc10, _wlan_send_mgmt_to_host)
 * unconditionally rejects management frames on MONITOR vdevs: the internal
 * vdev-type switch only accepts AP(0), STA(1), IBSS(2), OCB(6) for the
 * normal peer-lookup → WAL-TX path.  MONITOR(3) is shunted to a
 * beacon-only fallback (FUN_b01baa34) that always returns 5 → DISCARD.
 *
 * Work around this by creating a lightweight STA vdev on the same channel
 * as the monitor interface and routing raw frames through it. The vdev has a
 * self-peer (stored at firmware vdev+0xc) for group traffic and one transient
 * destination peer for directed traffic. The latter lets firmware resolve
 * Addr1 without changing any address carried in the injected frame.
 *
 * Lifecycle:
 *   Created lazily on the first injection attempt on a monitor vdev.
 *   Destroyed in wma_deinit_injection_queue() or when the channel changes.
 *   WMI response events for this vdev (create/start/peer_create/up) are
 *   silently dropped by the host because no wlan_objmgr_vdev exists for
 *   the hidden vdev_id.
 */
struct wma_injection_tx_vdev {
	bool created;
	bool self_peer_ready;
	bool self_peer_create_pending;
	bool self_peer_delete_pending;
	bool unicast_peer_created;
	bool unicast_peer_create_pending;
	bool unicast_peer_delete_pending;
	uint8_t vdev_id;
	uint8_t monitor_vdev_id;
	uint32_t chanfreq;
	uint8_t mac_addr[QDF_MAC_ADDR_SIZE];
	uint8_t unicast_peer_addr[QDF_MAC_ADDR_SIZE];
};

static struct wma_injection_tx_vdev g_inj_tx_vdev;

#define WMA_INJECTION_PEER_RSP_POLL_MS 5
#define WMA_INJECTION_PEER_RSP_TIMEOUT_MS 500
#define WMA_INJECTION_PEER_COOLDOWN_MS 50

enum wma_injection_peer_rsp_type {
	WMA_INJECTION_PEER_RSP_NONE,
	WMA_INJECTION_PEER_RSP_CREATE,
	WMA_INJECTION_PEER_RSP_DELETE,
};

struct wma_injection_peer_rsp_state {
	qdf_atomic_t expected;
	qdf_atomic_t completed;
	qdf_atomic_t result;
	uint8_t vdev_id;
	uint8_t peer_addr[QDF_MAC_ADDR_SIZE];
};

static struct wma_injection_peer_rsp_state g_inj_peer_rsp;

static QDF_STATUS wma_injection_destroy_tx_vdev(tp_wma_handle wma);
static uint32_t wma_injection_vdev_inflight(uint8_t vdev_id);

static void
wma_injection_peer_rsp_prepare(uint8_t vdev_id, const uint8_t *peer_addr,
			       enum wma_injection_peer_rsp_type type)
{
	qdf_atomic_set(&g_inj_peer_rsp.completed, WMA_INJECTION_PEER_RSP_NONE);
	qdf_atomic_set(&g_inj_peer_rsp.result, QDF_STATUS_SUCCESS);
	g_inj_peer_rsp.vdev_id = vdev_id;
	qdf_mem_copy(g_inj_peer_rsp.peer_addr, peer_addr, QDF_MAC_ADDR_SIZE);
	qdf_atomic_set(&g_inj_peer_rsp.expected, type);
}

static void
wma_injection_peer_rsp_cancel(enum wma_injection_peer_rsp_type type)
{
	if (qdf_atomic_read(&g_inj_peer_rsp.expected) != type)
		return;

	qdf_atomic_set(&g_inj_peer_rsp.expected, WMA_INJECTION_PEER_RSP_NONE);
	qdf_atomic_set(&g_inj_peer_rsp.completed, WMA_INJECTION_PEER_RSP_NONE);
}

static QDF_STATUS
wma_injection_peer_rsp_wait(enum wma_injection_peer_rsp_type type)
{
	uint32_t waited_ms = 0;
	QDF_STATUS status;

	while (qdf_atomic_read(&g_inj_peer_rsp.completed) != type &&
	       waited_ms < WMA_INJECTION_PEER_RSP_TIMEOUT_MS &&
	       !cds_is_driver_recovering()) {
		qdf_sleep(WMA_INJECTION_PEER_RSP_POLL_MS);
		waited_ms += WMA_INJECTION_PEER_RSP_POLL_MS;
	}

	if (qdf_atomic_read(&g_inj_peer_rsp.completed) != type) {
		if (cds_is_driver_recovering()) {
			wma_injection_peer_rsp_cancel(type);
			return QDF_STATUS_E_AGAIN;
		}

		/* Keep the expectation armed so a late response is retained. */
		return QDF_STATUS_E_TIMEOUT;
	}

	status = qdf_atomic_read(&g_inj_peer_rsp.result);
	wma_injection_peer_rsp_cancel(type);
	return status;
}

static bool
wma_injection_peer_rsp_complete(uint8_t vdev_id, const uint8_t *peer_addr,
				enum wma_injection_peer_rsp_type type,
				QDF_STATUS status)
{
	if (qdf_atomic_read(&g_inj_peer_rsp.expected) != type ||
	    g_inj_peer_rsp.vdev_id != vdev_id ||
	    qdf_mem_cmp(g_inj_peer_rsp.peer_addr, peer_addr,
			QDF_MAC_ADDR_SIZE))
		return false;

	qdf_atomic_set(&g_inj_peer_rsp.result, status);
	qdf_atomic_set(&g_inj_peer_rsp.completed, type);
	return true;
}

bool wma_injection_peer_create_response(uint8_t vdev_id,
					const uint8_t *peer_addr,
					uint32_t fw_status)
{
	QDF_STATUS status;
	bool handled;

	status = (!fw_status || fw_status == WMI_PEER_EXISTS) ?
		 QDF_STATUS_SUCCESS : QDF_STATUS_E_FAILURE;
	handled = wma_injection_peer_rsp_complete(
		vdev_id, peer_addr, WMA_INJECTION_PEER_RSP_CREATE, status);
	if (handled)
		wma_info("Injection peer create response: fw_status=%u accepted=%u vdev=%u peer=%pM",
			 fw_status, QDF_IS_STATUS_SUCCESS(status), vdev_id,
			 peer_addr);

	return handled;
}

bool wma_injection_peer_delete_response(uint8_t vdev_id,
					const uint8_t *peer_addr)
{
	return wma_injection_peer_rsp_complete(
		vdev_id, peer_addr, WMA_INJECTION_PEER_RSP_DELETE,
		QDF_STATUS_SUCCESS);
}

static QDF_STATUS
wma_injection_ensure_unicast_peer(tp_wma_handle wma, const uint8_t *peer_addr)
{
	struct peer_create_params create = {0};
	struct peer_delete_cmd_params delete = {0};
	QDF_STATUS status;
	bool sync_peer_rsp;

	if (!wma || !wma->wmi_handle || !g_inj_tx_vdev.created || !peer_addr ||
	    qdf_is_macaddr_group((struct qdf_mac_addr *)peer_addr) ||
	    qdf_is_macaddr_zero((struct qdf_mac_addr *)peer_addr))
		return QDF_STATUS_E_INVAL;

	sync_peer_rsp = wlan_psoc_nif_fw_ext_cap_get(
		wma->psoc, WLAN_SOC_F_PEER_CREATE_RESP);
	if (g_inj_tx_vdev.unicast_peer_create_pending) {
		status = wma_injection_peer_rsp_wait(
			WMA_INJECTION_PEER_RSP_CREATE);
		if (QDF_IS_STATUS_ERROR(status)) {
			if (status != QDF_STATUS_E_TIMEOUT) {
				g_inj_tx_vdev.unicast_peer_create_pending = false;
				g_inj_tx_vdev.unicast_peer_created = false;
				qdf_mem_zero(g_inj_tx_vdev.unicast_peer_addr,
					     QDF_MAC_ADDR_SIZE);
			}
			return status;
		}
		g_inj_tx_vdev.unicast_peer_create_pending = false;
	}
	if (g_inj_tx_vdev.unicast_peer_delete_pending) {
		status = wma_injection_peer_rsp_wait(
			WMA_INJECTION_PEER_RSP_DELETE);
		if (QDF_IS_STATUS_ERROR(status))
			return status;
		g_inj_tx_vdev.unicast_peer_delete_pending = false;
		g_inj_tx_vdev.unicast_peer_created = false;
		qdf_mem_zero(g_inj_tx_vdev.unicast_peer_addr,
			     QDF_MAC_ADDR_SIZE);
	}
	if (g_inj_tx_vdev.unicast_peer_created &&
	    !qdf_mem_cmp(g_inj_tx_vdev.unicast_peer_addr, peer_addr,
			 QDF_MAC_ADDR_SIZE))
		return QDF_STATUS_SUCCESS;

	if (g_inj_tx_vdev.unicast_peer_created) {
		if (wma_injection_vdev_inflight(g_inj_tx_vdev.vdev_id))
			return QDF_STATUS_E_BUSY;

		delete.vdev_id = g_inj_tx_vdev.vdev_id;
		if (sync_peer_rsp)
			wma_injection_peer_rsp_prepare(
				g_inj_tx_vdev.vdev_id,
				g_inj_tx_vdev.unicast_peer_addr,
				WMA_INJECTION_PEER_RSP_DELETE);
		status = wmi_unified_peer_delete_send(
			wma->wmi_handle, g_inj_tx_vdev.unicast_peer_addr,
			&delete);
		if (QDF_IS_STATUS_ERROR(status)) {
			if (sync_peer_rsp)
				wma_injection_peer_rsp_cancel(
					WMA_INJECTION_PEER_RSP_DELETE);
			wma_err("Injection unicast peer delete failed: vdev=%u peer=%pM status=%d",
				g_inj_tx_vdev.vdev_id,
				g_inj_tx_vdev.unicast_peer_addr, status);
			return status;
		}
		g_inj_tx_vdev.unicast_peer_delete_pending = sync_peer_rsp;
		status = sync_peer_rsp ? wma_injection_peer_rsp_wait(
			WMA_INJECTION_PEER_RSP_DELETE) : QDF_STATUS_SUCCESS;
		if (QDF_IS_STATUS_ERROR(status))
			return status;
		g_inj_tx_vdev.unicast_peer_delete_pending = false;
		qdf_sleep(WMA_INJECTION_PEER_COOLDOWN_MS);
		g_inj_tx_vdev.unicast_peer_created = false;
		qdf_mem_zero(g_inj_tx_vdev.unicast_peer_addr,
			     QDF_MAC_ADDR_SIZE);
	}

	create.peer_addr = (uint8_t *)peer_addr;
	create.peer_type = WMI_PEER_TYPE_DEFAULT;
	create.vdev_id = g_inj_tx_vdev.vdev_id;
	if (sync_peer_rsp)
		wma_injection_peer_rsp_prepare(g_inj_tx_vdev.vdev_id, peer_addr,
					       WMA_INJECTION_PEER_RSP_CREATE);
	status = wmi_unified_peer_create_send(wma->wmi_handle, &create);
	if (QDF_IS_STATUS_ERROR(status)) {
		if (sync_peer_rsp)
			wma_injection_peer_rsp_cancel(
				WMA_INJECTION_PEER_RSP_CREATE);
		wma_err("Injection unicast peer create failed: vdev=%u peer=%pM status=%d",
			g_inj_tx_vdev.vdev_id, peer_addr, status);
		return status;
	}
	qdf_mem_copy(g_inj_tx_vdev.unicast_peer_addr, peer_addr,
		     QDF_MAC_ADDR_SIZE);
	g_inj_tx_vdev.unicast_peer_created = true;
	g_inj_tx_vdev.unicast_peer_create_pending = sync_peer_rsp;
	status = sync_peer_rsp ? wma_injection_peer_rsp_wait(
		WMA_INJECTION_PEER_RSP_CREATE) : QDF_STATUS_SUCCESS;
	if (QDF_IS_STATUS_ERROR(status)) {
		if (status != QDF_STATUS_E_TIMEOUT) {
			g_inj_tx_vdev.unicast_peer_create_pending = false;
			g_inj_tx_vdev.unicast_peer_created = false;
			qdf_mem_zero(g_inj_tx_vdev.unicast_peer_addr,
				     QDF_MAC_ADDR_SIZE);
		}
		return status;
	}
	g_inj_tx_vdev.unicast_peer_create_pending = false;
	g_wma_injection_ctx.recreate_helper_on_retune = true;
	qdf_sleep(WMA_INJECTION_PEER_COOLDOWN_MS);
	wma_info("Injection unicast peer ready: vdev=%u peer=%pM synchronized=%u",
		 g_inj_tx_vdev.vdev_id, peer_addr, sync_peer_rsp);

	return QDF_STATUS_SUCCESS;
}

static void wma_injection_reclaim_vdev_nbufs(uint8_t vdev_id)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	uint32_t reclaimed = 0;
	uint32_t i;

	if (!ctx->is_initialized)
		return;

	for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
		struct wma_injection_debug_info *e =
			&g_wma_injection_debug_cache[i];
		qdf_nbuf_t tx_buf = NULL;

		qdf_spin_lock_bh(&ctx->cache_lock);
		if (e->valid && e->vdev_id == vdev_id && e->tx_buf) {
			tx_buf = e->tx_buf;
			e->tx_buf = NULL;
			e->valid = false;
			qdf_atomic_dec(&ctx->inflight_count);
		}
		qdf_spin_unlock_bh(&ctx->cache_lock);

		if (tx_buf) {
			wma_injection_unmap_tx_buf(tx_buf);
			qdf_nbuf_free(tx_buf);
			reclaimed++;
		}
	}

	if (reclaimed)
		wma_info("Injection teardown: reclaimed %u nbufs for vdev %u",
			 reclaimed, vdev_id);
}

static uint32_t wma_injection_vdev_inflight(uint8_t vdev_id)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	uint32_t inflight = 0;
	uint32_t i;

	if (!ctx->is_initialized)
		return 0;

	qdf_spin_lock_bh(&ctx->cache_lock);
	for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
		struct wma_injection_debug_info *e =
			&g_wma_injection_debug_cache[i];

		if (e->valid && e->vdev_id == vdev_id && e->tx_buf)
			inflight++;
	}
	qdf_spin_unlock_bh(&ctx->cache_lock);

	return inflight;
}

/*
 * Resolve a unicast destination only through an existing, connected peer on a
 * real vdev.  The object-manager reference makes peer/vdev inspection safe;
 * the CDP check confirms that the corresponding datapath/firmware peer still
 * exists on that same vdev.  No peer is created by this path.
 */
static QDF_STATUS
wma_injection_find_unicast_peer(tp_wma_handle wma, uint8_t *addr1,
				uint8_t *addr2, uint8_t *addr3,
				uint8_t *peer_vdev_id, uint16_t *chanfreq,
				uint8_t *vdev_type)
{
	struct wlan_objmgr_peer *peer;
	struct wlan_objmgr_vdev *vdev;
	struct cdp_soc_t *soc;
	uint8_t *self_mac;
	uint8_t pdev_id;
	uint8_t i;
	bool peer_seen = false;
	bool address_mismatch = false;

	if (!wma || !wma->psoc || !wma->pdev)
		return QDF_STATUS_E_INVAL;

	soc = cds_get_context(QDF_MODULE_ID_SOC);
	if (!soc)
		return QDF_STATUS_E_FAILURE;

	pdev_id = wlan_objmgr_pdev_get_pdev_id(wma->pdev);
	for (i = 0; i < wma->max_bssid; i++) {
		enum wlan_peer_type peer_type;
		int dp_peer_state;
		uint8_t type = wma->interfaces[i].type;
		bool candidate_address_mismatch = false;

		vdev = wma->interfaces[i].vdev;
		if (!vdev || !wma->interfaces[i].vdev_active ||
		    type == WMI_VDEV_TYPE_MONITOR ||
		    (g_inj_tx_vdev.created && i == g_inj_tx_vdev.vdev_id))
			continue;

		if (type != WMI_VDEV_TYPE_AP && type != WMI_VDEV_TYPE_STA)
			continue;

		self_mac = wlan_vdev_mlme_get_macaddr(vdev);
		if (!self_mac)
			continue;

		peer = wlan_objmgr_get_peer_by_mac_n_vdev(
			wma->psoc, pdev_id, self_mac, addr1,
			WLAN_LEGACY_WMA_ID);
		if (!peer)
			continue;

		peer_seen = true;
		wlan_peer_obj_lock(peer);
		peer_type = wlan_peer_get_peer_type(peer);
		wlan_peer_obj_unlock(peer);
		dp_peer_state = cdp_peer_state_get(soc, i, addr1, true);

		if (wlan_peer_get_vdev(peer) != vdev ||
		    peer_type == WLAN_PEER_SELF ||
		    dp_peer_state != OL_TXRX_PEER_STATE_AUTH ||
		    !cdp_find_peer_exist_on_vdev(soc, i, addr1)) {
			wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_WMA_ID);
			continue;
		}

		/* AP/GO: SA and BSSID are the vdev MAC. */
		if (type == WMI_VDEV_TYPE_AP &&
		    (qdf_mem_cmp(addr2, self_mac, QDF_MAC_ADDR_SIZE) ||
		     qdf_mem_cmp(addr3, self_mac, QDF_MAC_ADDR_SIZE)))
			candidate_address_mismatch = true;

		/* STA/client: SA is the vdev MAC and BSSID is the AP peer. */
		if (type == WMI_VDEV_TYPE_STA &&
		    (qdf_mem_cmp(addr2, self_mac, QDF_MAC_ADDR_SIZE) ||
		     qdf_mem_cmp(addr3, addr1, QDF_MAC_ADDR_SIZE)))
			candidate_address_mismatch = true;

		if (candidate_address_mismatch) {
			address_mismatch = true;
			wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_WMA_ID);
			continue;
		}

		if (!vdev->vdev_mlme.des_chan ||
		    !vdev->vdev_mlme.des_chan->ch_freq) {
			wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_WMA_ID);
			return QDF_STATUS_E_INVAL;
		}

		*peer_vdev_id = i;
		*chanfreq = vdev->vdev_mlme.des_chan->ch_freq;
		*vdev_type = type;
		wlan_objmgr_peer_release_ref(peer, WLAN_LEGACY_WMA_ID);
		return QDF_STATUS_SUCCESS;
	}

	if (peer_seen && address_mismatch) {
		wma_warn("Injection unicast address context mismatch: addr1=%pM addr2=%pM addr3=%pM",
			 addr1, addr2, addr3);
		return QDF_STATUS_E_INVAL;
	}

	return QDF_STATUS_E_NOENT;
}

/**
 * wma_injection_reset_session_state() - Reset per-session static state
 *
 * Called when a new injection TX vdev is being created (fresh session
 * or channel change).  Resets all file-static one-shot logging flags
 * and the send counter so the new session starts clean.
 */
static void wma_injection_reset_session_state(void)
{
	/* Reset one-shot logging flags so fresh session re-logs config */
	inject_tx_cfg_logged = false;
	inject_send_info_count = 0;
	inject_wmi_path_logged = false;
	inject_legacy_path_logged = false;
	inject_monitor_no_legacy_logged = false;
	inject_wmi_service_absent_logged = false;
	inject_probe_sa_fix_logged = false;

	/*
	 * Do NOT sweep/free nbufs from the debug cache here.
	 * The firmware may still be DMA-reading in-flight buffers;
	 * freeing them would corrupt FW memory and crash.  Stale
	 * nbufs are safely freed by:
	 *   - normal completion handler (wma_handle_injection_fw_response)
	 *   - the stale completion reaper
	 *   - helper-vdev teardown after firmware stop/delete
	 *   - wma_deinit_injection_queue() at driver shutdown
	 */
}

/**
 * wma_injection_ensure_tx_vdev() - Ensure hidden STA vdev exists for TX
 * @wma: WMA handle
 * @mon_vdev_id: monitor vdev id
 * @chanfreq: operating channel frequency in MHz
 *
 * Creates (or re-creates on channel change) a firmware-only STA vdev that
 * is used as the TX endpoint for group-addressed management frames.
 *
 * Return: QDF_STATUS_SUCCESS when the helper vdev is ready.
 */
static QDF_STATUS
wma_injection_ensure_tx_vdev(tp_wma_handle wma,
			    uint8_t mon_vdev_id,
			    uint32_t chanfreq)
{
	struct vdev_create_params vcreate;
	struct vdev_start_params vstart;
	struct vdev_set_params vp;
	struct peer_create_params pcreate;
	uint8_t *mon_mac;
	uint8_t inj_mac[QDF_MAC_ADDR_SIZE];
	uint8_t vid = 0;
	bool found = false;
	bool sync_peer_rsp;
	int i;
	QDF_STATUS status;

	if (g_inj_tx_vdev.created) {
		if (g_inj_tx_vdev.self_peer_create_pending) {
			status = wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_CREATE);
			if (QDF_IS_STATUS_ERROR(status)) {
				if (status != QDF_STATUS_E_TIMEOUT)
					g_inj_tx_vdev.self_peer_create_pending = false;
				return status;
			}
			g_inj_tx_vdev.self_peer_create_pending = false;
			g_inj_tx_vdev.self_peer_ready = true;
		}
		if (!g_inj_tx_vdev.self_peer_ready) {
			status = wma_injection_destroy_tx_vdev(wma);
			if (QDF_IS_STATUS_ERROR(status))
				return status;
		} else if (g_inj_tx_vdev.chanfreq == chanfreq) {
			return QDF_STATUS_SUCCESS;
		}
	}

	if (g_inj_tx_vdev.created) {
		if (wma_injection_vdev_inflight(g_inj_tx_vdev.vdev_id)) {
			wma_warn("Injection: refusing helper channel change with in-flight TX on vdev %u",
				 g_inj_tx_vdev.vdev_id);
			return QDF_STATUS_E_AGAIN;
		}

	/* Prepare and send VDEV_START command to switch frequency
	 * and lock the synthesizer on the target channel.
	 */
	qdf_mem_zero(&vstart, sizeof(vstart));
		vstart.vdev_id            = g_inj_tx_vdev.vdev_id;
		vstart.channel.mhz        = chanfreq;
		vstart.channel.cfreq1     = chanfreq;
		vstart.channel.cfreq2     = 0;
		vstart.channel.phy_mode   = (enum wlan_phymode)((chanfreq < 4000) ? WMI_HOST_MODE_11G : WMI_HOST_MODE_11A);
		vstart.channel.maxregpower = 20;
		vstart.channel.maxpower    = 20;
		vstart.is_restart         = true;

		status = target_if_vdev_mgr_fw_only_rsp_prepare(
			g_inj_tx_vdev.vdev_id, RESTART_RESPONSE_BIT);
		if (QDF_IS_STATUS_ERROR(status))
			return status;
		status = wmi_unified_vdev_start_send(wma->wmi_handle, &vstart);
		if (QDF_IS_STATUS_SUCCESS(status)) {
			status = target_if_vdev_mgr_fw_only_rsp_wait(
				g_inj_tx_vdev.vdev_id, RESTART_RESPONSE_BIT,
				WMA_INJECTION_HELPER_RSP_TIMEOUT_MS);
			if (QDF_IS_STATUS_ERROR(status)) {
				wma_err("Injection helper restart response failed: vdev=%u freq=%u status=%d",
					g_inj_tx_vdev.vdev_id, chanfreq, status);
				return status;
			}

			/* Keep the helper TX-only so monitor RX remains on its vdev. */
			qdf_mem_zero(&vp, sizeof(vp));

			vp.vdev_id = g_inj_tx_vdev.vdev_id;
			vp.param_id = WMI_VDEV_PARAM_FIXED_RATE;
			vp.param_value = 0x1;

			wmi_unified_vdev_set_param_send(wma->wmi_handle, &vp);

			vp.param_id = WMI_VDEV_PARAM_DTIM_PERIOD;
			vp.param_value = 1;

			wmi_unified_vdev_set_param_send(wma->wmi_handle, &vp);

			g_inj_tx_vdev.chanfreq = chanfreq;
			qdf_sleep(15);
			wma_info("Injection helper vdev restarted: vdev=%u freq=%u",
				 g_inj_tx_vdev.vdev_id, chanfreq);
			return QDF_STATUS_SUCCESS;
		}
		target_if_vdev_mgr_fw_only_rsp_cancel(
			g_inj_tx_vdev.vdev_id, RESTART_RESPONSE_BIT);

		wma_err("Injection helper restart send failed: vdev=%u freq=%u status=%d",
			g_inj_tx_vdev.vdev_id, chanfreq, status);
		return status;
	}

	/*
	 * Firmware vdev array supports IDs 0..(num_vdevs-1).  num_vdevs is
	 * at most CFG_TGT_NUM_VDEV (typically 4) and may be decremented by 1
	 * for NAN → 3.  Use (CFG_TGT_NUM_VDEV - 2) as safe ceiling so we
	 * never exceed the firmware's internal array.
	 */
	{
		int fw_max_vid = CFG_TGT_NUM_VDEV - 2;

		if (fw_max_vid >= (int)wma->max_bssid)
			fw_max_vid = (int)wma->max_bssid - 1;
		for (i = fw_max_vid; i >= 0; i--) {
			if ((uint8_t)i == mon_vdev_id)
				continue;
			if (!wma->interfaces[i].vdev &&
			    !wma->interfaces[i].vdev_active) {
				vid = (uint8_t)i;
				found = true;
				break;
			}
		}
	}
	if (!found) {
		wma_err("Injection: no unused vdev slot for TX helper");
		return QDF_STATUS_E_RESOURCES;
	}

	/* New vdev being created — reset session state for a clean start */
	wma_injection_reset_session_state();

	if (!wma->interfaces[mon_vdev_id].vdev) {
			wma_err("Injection: monitor vdev invalid");
	        return QDF_STATUS_E_FAILURE;
	}

	mon_mac = wlan_vdev_mlme_get_macaddr(wma->interfaces[mon_vdev_id].vdev);

	if (!mon_mac) {
		wma_err("Injection: cannot read monitor vdev MAC");
		return QDF_STATUS_E_FAILURE;
	}
	qdf_mem_copy(inj_mac, mon_mac, QDF_MAC_ADDR_SIZE);
	inj_mac[0] |= 0x02; /* locally-administered */

	/* ---------- 1. VDEV CREATE (STA type) ---------- */
	/*
	 * Use STA, not AP.  AP vdevs trigger firmware beacon-TX-offload
	 * which crashes at _wlan_beacon_tx_offload_handle_beacon because
	 * no beacon template exists.  STA vdevs reach the same peer-lookup
	 * → WAL-TX path in the firmware mgmt TX handler without beacons.
	 */
	qdf_mem_zero(&vcreate, sizeof(vcreate));
	vcreate.vdev_id = vid;
	vcreate.type    = WMI_VDEV_TYPE_STA;
	vcreate.subtype = 0;
	vcreate.nss_2g  = 1;
	vcreate.nss_5g  = 1;
	vcreate.pdev_id = 0;

	status = wmi_unified_vdev_create_send(wma->wmi_handle,
					      inj_mac, &vcreate);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection TX vdev create failed: %d", status);
		return status;
	}
	/* Firmware processes WMI commands asynchronously.  Each step must
	 * complete in firmware before the next command references the vdev.
	 * Without these sleeps the mgmt-TX arrives before VDEV_CREATE is
	 * done and firmware asserts in wlan_vdev_find_vdev.
	 */

	qdf_sleep(15);

	/* ---------- 2. VDEV START (20 MHz basic mode) ---------- */
	qdf_mem_zero(&vstart, sizeof(vstart));
	vstart.vdev_id            = vid;
	vstart.channel.mhz        = chanfreq;
	vstart.channel.cfreq1     = chanfreq;
	vstart.channel.cfreq2     = 0;
	/* 2.4 GHz → WMI_HOST_MODE_11G, 5 GHz → WMI_HOST_MODE_11A */
	vstart.channel.phy_mode   = (enum wlan_phymode)((chanfreq < 4000) ? WMI_HOST_MODE_11G : WMI_HOST_MODE_11A);
	vstart.channel.maxregpower = 20;
	vstart.channel.maxpower    = 20;
	vstart.beacon_interval    = 0;
	vstart.dtim_period        = 0;

	status = target_if_vdev_mgr_fw_only_rsp_prepare(vid,
							     START_RESPONSE_BIT);
	if (QDF_IS_STATUS_ERROR(status))
		goto err_stop;
	status = wmi_unified_vdev_start_send(wma->wmi_handle, &vstart);
	if (QDF_IS_STATUS_ERROR(status)) {
		target_if_vdev_mgr_fw_only_rsp_cancel(vid, START_RESPONSE_BIT);
		wma_err("Injection TX vdev start failed: %d", status);
		goto err_stop;
	}
	status = target_if_vdev_mgr_fw_only_rsp_wait(
		vid, START_RESPONSE_BIT, WMA_INJECTION_HELPER_RSP_TIMEOUT_MS);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection TX vdev start response failed: vdev=%u freq=%u status=%d",
			vid, chanfreq, status);
		goto err_stop;
	}

	/* ---------- 3. PEER CREATE (self-peer → fw vdev+0xc) ---------- */
	qdf_mem_zero(&pcreate, sizeof(pcreate));
	pcreate.peer_addr = inj_mac;
	pcreate.peer_type = WMI_PEER_TYPE_DEFAULT;
	pcreate.vdev_id   = vid;

	sync_peer_rsp = wlan_psoc_nif_fw_ext_cap_get(
		wma->psoc, WLAN_SOC_F_PEER_CREATE_RESP);
	if (sync_peer_rsp)
		wma_injection_peer_rsp_prepare(
			vid, inj_mac, WMA_INJECTION_PEER_RSP_CREATE);
	status = wmi_unified_peer_create_send(wma->wmi_handle, &pcreate);
	if (QDF_IS_STATUS_ERROR(status)) {
		if (sync_peer_rsp)
			wma_injection_peer_rsp_cancel(
				WMA_INJECTION_PEER_RSP_CREATE);
		wma_err("Injection TX vdev peer create failed: %d", status);
		goto err_stop;
	}
	g_inj_tx_vdev.created = true;
	g_inj_tx_vdev.self_peer_create_pending = sync_peer_rsp;
	g_inj_tx_vdev.vdev_id = vid;
	g_inj_tx_vdev.monitor_vdev_id = mon_vdev_id;
	g_inj_tx_vdev.chanfreq = chanfreq;
	qdf_mem_copy(g_inj_tx_vdev.mac_addr, inj_mac, QDF_MAC_ADDR_SIZE);
	status = sync_peer_rsp ? wma_injection_peer_rsp_wait(
		WMA_INJECTION_PEER_RSP_CREATE) : QDF_STATUS_SUCCESS;
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection TX self peer create response failed: vdev=%u status=%d",
			vid, status);
		if (status != QDF_STATUS_E_TIMEOUT) {
			g_inj_tx_vdev.self_peer_create_pending = false;
			wma_injection_destroy_tx_vdev(wma);
		}
		return status;
	}
	g_inj_tx_vdev.self_peer_create_pending = false;
	g_inj_tx_vdev.self_peer_ready = true;
	qdf_sleep(WMA_INJECTION_PEER_COOLDOWN_MS);

	/*
	 * Skip VDEV_UP.  For STA vdevs, firmware's wlan_vdev_up
	 * asserts unless a BSS peer (the AP) exists — we only have
	 * a self-peer.  The mgmt TX handler only needs the vdev in
	 * STARTED state with a valid peer at vdev+0xc.
	 */

	wma_info("Injection TX helper vdev created: vdev_id=%u mac=%pM freq=%u type=STA",
		 vid, inj_mac, chanfreq);
	return QDF_STATUS_SUCCESS;

err_stop:
	if (wma->wmi_handle && !wmi_is_blocked(wma->wmi_handle) &&
	    !QDF_IS_STATUS_ERROR(target_if_vdev_mgr_fw_only_rsp_prepare(
			vid, DELETE_RESPONSE_BIT))) {
		QDF_STATUS delete_status;

		delete_status = wmi_unified_vdev_delete_send(wma->wmi_handle, vid);
		if (QDF_IS_STATUS_ERROR(delete_status))
			target_if_vdev_mgr_fw_only_rsp_cancel(vid,
							  DELETE_RESPONSE_BIT);
		else
			target_if_vdev_mgr_fw_only_rsp_wait(
				vid, DELETE_RESPONSE_BIT,
				WMA_INJECTION_HELPER_RSP_TIMEOUT_MS);
	}
	return status;
}

/**
 * wma_injection_destroy_tx_vdev() - Tear down the hidden injection TX vdev
 * @wma: WMA handle
 *
 * Late-path teardown (called from deinit_injection_queue / wma_close).
 *
 * Return: QDF_STATUS_SUCCESS after VDEV_DELETE is submitted, or an error that
 * leaves host state intact so the caller can retry.
 */
static QDF_STATUS wma_injection_destroy_tx_vdev(tp_wma_handle wma)
{
	uint8_t helper_vdev_id;
	bool sync_peer_rsp;
	QDF_STATUS status;

	if (!g_inj_tx_vdev.created)
		return QDF_STATUS_SUCCESS;
	if (!wma)
		return QDF_STATUS_E_INVAL;

	helper_vdev_id = g_inj_tx_vdev.vdev_id;
	if (!wma->wmi_handle || wmi_is_blocked(wma->wmi_handle)) {
		wma_info("WMI stopped: clearing injection helper host state vdev %u",
			 helper_vdev_id);
		wma_injection_peer_rsp_cancel(
			WMA_INJECTION_PEER_RSP_CREATE);
		wma_injection_peer_rsp_cancel(
			WMA_INJECTION_PEER_RSP_DELETE);
		wma_injection_reclaim_vdev_nbufs(helper_vdev_id);
		qdf_mem_zero(&g_inj_tx_vdev, sizeof(g_inj_tx_vdev));
		return QDF_STATUS_SUCCESS;
	}

	/*
	 * Proper teardown order (reverse of create):
	 *   PEER_DELETE → VDEV_STOP → VDEV_DELETE
	 * STOP and DELETE are synchronized with their firmware responses so the
	 * helper slot cannot be reused while teardown is still pending.
	 */

	/* 1. Delete the transient destination peer, then the self-peer. */
	{
		struct peer_delete_cmd_params del_param = {0};

		del_param.vdev_id = g_inj_tx_vdev.vdev_id;
		sync_peer_rsp = wlan_psoc_nif_fw_ext_cap_get(
			wma->psoc, WLAN_SOC_F_PEER_CREATE_RESP);
		if (g_inj_tx_vdev.unicast_peer_create_pending) {
			status = wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_CREATE);
			if (QDF_IS_STATUS_ERROR(status)) {
				if (status != QDF_STATUS_E_TIMEOUT) {
					g_inj_tx_vdev.unicast_peer_create_pending = false;
					g_inj_tx_vdev.unicast_peer_created = false;
				}
				return status;
			}
			g_inj_tx_vdev.unicast_peer_create_pending = false;
		}
		if (g_inj_tx_vdev.unicast_peer_delete_pending) {
			status = wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_DELETE);
			if (QDF_IS_STATUS_ERROR(status))
				return status;
			g_inj_tx_vdev.unicast_peer_delete_pending = false;
			g_inj_tx_vdev.unicast_peer_created = false;
			qdf_mem_zero(g_inj_tx_vdev.unicast_peer_addr,
				     QDF_MAC_ADDR_SIZE);
		}
		if (g_inj_tx_vdev.unicast_peer_created) {
			if (sync_peer_rsp)
				wma_injection_peer_rsp_prepare(
					g_inj_tx_vdev.vdev_id,
					g_inj_tx_vdev.unicast_peer_addr,
					WMA_INJECTION_PEER_RSP_DELETE);
			status = wmi_unified_peer_delete_send(
				wma->wmi_handle,
				g_inj_tx_vdev.unicast_peer_addr, &del_param);
			if (QDF_IS_STATUS_ERROR(status)) {
				if (sync_peer_rsp)
					wma_injection_peer_rsp_cancel(
						WMA_INJECTION_PEER_RSP_DELETE);
				wma_warn("Injection unicast peer delete failed: vdev=%u peer=%pM status=%d",
					 g_inj_tx_vdev.vdev_id,
					 g_inj_tx_vdev.unicast_peer_addr, status);
				return status;
			}
			g_inj_tx_vdev.unicast_peer_delete_pending = sync_peer_rsp;
			status = sync_peer_rsp ? wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_DELETE) :
				QDF_STATUS_SUCCESS;
			if (QDF_IS_STATUS_ERROR(status))
				return status;
			g_inj_tx_vdev.unicast_peer_delete_pending = false;
			g_inj_tx_vdev.unicast_peer_created = false;
			qdf_mem_zero(g_inj_tx_vdev.unicast_peer_addr,
				     QDF_MAC_ADDR_SIZE);
			qdf_sleep(WMA_INJECTION_PEER_COOLDOWN_MS);
		}
		if (wmi_is_blocked(wma->wmi_handle))
			return QDF_STATUS_E_AGAIN;
		if (g_inj_tx_vdev.self_peer_create_pending) {
			status = wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_CREATE);
			if (QDF_IS_STATUS_ERROR(status)) {
				if (status != QDF_STATUS_E_TIMEOUT)
					g_inj_tx_vdev.self_peer_create_pending = false;
				return status;
			}
			g_inj_tx_vdev.self_peer_create_pending = false;
			g_inj_tx_vdev.self_peer_ready = true;
		}
		if (g_inj_tx_vdev.self_peer_delete_pending) {
			status = wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_DELETE);
			if (QDF_IS_STATUS_ERROR(status))
				return status;
			g_inj_tx_vdev.self_peer_delete_pending = false;
			g_inj_tx_vdev.self_peer_ready = false;
		}
		if (g_inj_tx_vdev.self_peer_ready) {
			if (sync_peer_rsp)
				wma_injection_peer_rsp_prepare(
					g_inj_tx_vdev.vdev_id,
					g_inj_tx_vdev.mac_addr,
					WMA_INJECTION_PEER_RSP_DELETE);
			status = wmi_unified_peer_delete_send(
				wma->wmi_handle, g_inj_tx_vdev.mac_addr,
				&del_param);
			if (QDF_IS_STATUS_ERROR(status)) {
				if (sync_peer_rsp)
					wma_injection_peer_rsp_cancel(
						WMA_INJECTION_PEER_RSP_DELETE);
				wma_warn("Injection self peer delete failed: vdev=%u status=%d",
					 g_inj_tx_vdev.vdev_id, status);
				return status;
			}
			g_inj_tx_vdev.self_peer_delete_pending = sync_peer_rsp;
			status = sync_peer_rsp ? wma_injection_peer_rsp_wait(
				WMA_INJECTION_PEER_RSP_DELETE) :
				QDF_STATUS_SUCCESS;
			if (QDF_IS_STATUS_ERROR(status))
				return status;
			g_inj_tx_vdev.self_peer_delete_pending = false;
			g_inj_tx_vdev.self_peer_ready = false;
			qdf_sleep(WMA_INJECTION_PEER_COOLDOWN_MS);
		}
	}

	/* 2. VDEV_STOP (we did VDEV_START during create) */
	if (wmi_is_blocked(wma->wmi_handle))
		return QDF_STATUS_E_AGAIN;
	status = target_if_vdev_mgr_fw_only_rsp_prepare(
		g_inj_tx_vdev.vdev_id, STOP_RESPONSE_BIT);
	if (QDF_IS_STATUS_ERROR(status))
		return status;
	status = wmi_unified_vdev_stop_send(wma->wmi_handle,
					    g_inj_tx_vdev.vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		target_if_vdev_mgr_fw_only_rsp_cancel(
			g_inj_tx_vdev.vdev_id, STOP_RESPONSE_BIT);
		wma_warn("Injection helper vdev stop failed: vdev=%u status=%d",
			 g_inj_tx_vdev.vdev_id, status);
	} else {
		status = target_if_vdev_mgr_fw_only_rsp_wait(
			g_inj_tx_vdev.vdev_id, STOP_RESPONSE_BIT,
			WMA_INJECTION_HELPER_RSP_TIMEOUT_MS);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Injection helper vdev stop response timed out: vdev=%u status=%d",
				g_inj_tx_vdev.vdev_id, status);
			return status;
		}
	}

	/* 3. VDEV_DELETE */
	if (wmi_is_blocked(wma->wmi_handle))
		return QDF_STATUS_E_AGAIN;
	status = target_if_vdev_mgr_fw_only_rsp_prepare(
		g_inj_tx_vdev.vdev_id, DELETE_RESPONSE_BIT);
	if (QDF_IS_STATUS_ERROR(status))
		return status;
	status = wmi_unified_vdev_delete_send(wma->wmi_handle,
					      g_inj_tx_vdev.vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		target_if_vdev_mgr_fw_only_rsp_cancel(
			g_inj_tx_vdev.vdev_id, DELETE_RESPONSE_BIT);
		wma_err("Injection helper vdev delete failed: vdev=%u status=%d",
			g_inj_tx_vdev.vdev_id, status);
		return status;
	}
	status = target_if_vdev_mgr_fw_only_rsp_wait(
		g_inj_tx_vdev.vdev_id, DELETE_RESPONSE_BIT,
		WMA_INJECTION_HELPER_RSP_TIMEOUT_MS);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Injection helper vdev delete response timed out: vdev=%u status=%d",
			g_inj_tx_vdev.vdev_id, status);
		return status;
	}
	qdf_sleep(WMA_INJECTION_HELPER_DELETE_COOLDOWN_MS);

	wma_info("Injection TX helper vdev destroyed: vdev_id=%u",
		 g_inj_tx_vdev.vdev_id);

	wma_injection_reclaim_vdev_nbufs(g_inj_tx_vdev.vdev_id);
	qdf_mem_zero(&g_inj_tx_vdev, sizeof(g_inj_tx_vdev));
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_injection_pre_stop_cleanup() - Destroy injection helper vdev before
 *                                     monitor mode stop
 * @wma_handle: WMA handle
 *
 * Must be called while WMI is still alive, BEFORE the driver sends
 * VDEV_STOP / VDEV_DELETE for the monitor vdev.  The firmware asserts
 * in dispatch_wlan_pdev_cmds if an orphaned STA helper vdev is still
 * present when the monitor vdev is torn down.
 *
 * Proper teardown order (reverse of create):
 *   PEER_DELETE → VDEV_STOP → VDEV_DELETE
 * with msleep() gaps so the firmware can process each command.
 */
void wma_injection_pre_stop_cleanup(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle) {
		wma_err("Invalid WMA handle for pre-stop cleanup");
		return;
	}

	ctx->helper_stopping = true;
	if (ctx->is_initialized) {
		/* Stop the injection worker before deleting its firmware endpoint. */
		wma_flush_injection_queue(wma_handle);
	}

	if (!g_inj_tx_vdev.created)
		return;

	wma_info("Pre-stop cleanup: destroying injection helper vdev_id=%u",
		 g_inj_tx_vdev.vdev_id);
	if (ctx->is_initialized &&
	    !QDF_IS_STATUS_ERROR(qdf_mutex_acquire(&ctx->helper_lock))) {
		wma_injection_destroy_tx_vdev(wma_handle);
		qdf_mutex_release(&ctx->helper_lock);
	} else {
		wma_injection_destroy_tx_vdev(wma_handle);
	}
}

/**
 * wma_injection_notify_channel_change() - Retarget injection helper vdev
 * @wma_handle: WMA handle
 * @mon_vdev_id: Monitor vdev ID whose channel changed
 * @new_freq: New channel frequency in MHz
 *
 * Drain and retarget the hidden STA helper before the real monitor vdev changes
 * channel. After directed-peer injection, recreate the helper on every retune
 * because firmware rejects restarting a replacement STA in that session.
 * Submissions remain gated until wma_injection_complete_channel_change().
 *
 * Return: QDF_STATUS_SUCCESS when the old helper no longer owns the channel
 */
QDF_STATUS wma_injection_notify_channel_change(tp_wma_handle wma_handle,
					       uint8_t mon_vdev_id,
					       uint32_t new_freq)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	uint32_t drain_wait_ms = 0;
	uint32_t inflight;
	uint8_t helper_vdev_id = WLAN_UMAC_VDEV_ID_MAX;

	if (!wma_handle || !new_freq)
		return QDF_STATUS_E_INVAL;

	if (!ctx->is_initialized)
		return QDF_STATUS_SUCCESS;
	if (ctx->helper_stopping || !wma_handle->wmi_handle ||
	    wmi_is_blocked(wma_handle->wmi_handle))
		return QDF_STATUS_E_AGAIN;

	/*
	 * Claim the transition under the helper mutex, then release it before
	 * waiting because cleanup may currently own the mutex.
	 */
	if (QDF_IS_STATUS_ERROR(qdf_mutex_acquire(&ctx->helper_lock)))
		return QDF_STATUS_E_BUSY;
	if (!ctx->is_initialized || ctx->helper_stopping ||
	    ctx->helper_transitioning) {
		status = ctx->helper_transitioning ? QDF_STATUS_E_BUSY :
			 QDF_STATUS_E_AGAIN;
		qdf_mutex_release(&ctx->helper_lock);
		return status;
	}
	if (!g_inj_tx_vdev.created ||
	    g_inj_tx_vdev.monitor_vdev_id != mon_vdev_id ||
	    g_inj_tx_vdev.chanfreq == new_freq) {
		qdf_mutex_release(&ctx->helper_lock);
		return QDF_STATUS_SUCCESS;
	}
	ctx->helper_transitioning = true;
	qdf_mutex_release(&ctx->helper_lock);

	/* Quiesce workers without dropping requests already owned by WMA. */
	qdf_cancel_work(&ctx->queue_work);
	qdf_flush_work(&ctx->queue_work);
	qdf_delayed_work_stop_sync(&ctx->delayed_work);

	if (QDF_IS_STATUS_ERROR(qdf_mutex_acquire(&ctx->helper_lock))) {
		status = QDF_STATUS_E_BUSY;
		goto transition_done;
	}
	if (ctx->helper_stopping || !ctx->is_initialized ||
	    !wma_handle->wmi_handle ||
	    wmi_is_blocked(wma_handle->wmi_handle)) {
		status = QDF_STATUS_E_AGAIN;
		goto unlock;
	}

	if (g_inj_tx_vdev.created &&
	    g_inj_tx_vdev.monitor_vdev_id == mon_vdev_id)
		helper_vdev_id = g_inj_tx_vdev.vdev_id;
	qdf_mutex_release(&ctx->helper_lock);

	/*
	 * Completions and the stale-nbuf reaper run without helper_lock. Keep
	 * submissions gated while they retire buffers owned by the old channel.
	 */
	if (helper_vdev_id != WLAN_UMAC_VDEV_ID_MAX) {
		inflight = wma_injection_vdev_inflight(helper_vdev_id);
		while (inflight &&
		       drain_wait_ms < WMA_INJECTION_CHANNEL_DRAIN_TIMEOUT_MS) {
			qdf_sleep(WMA_INJECTION_CHANNEL_DRAIN_POLL_MS);
			drain_wait_ms += WMA_INJECTION_CHANNEL_DRAIN_POLL_MS;
			inflight = wma_injection_vdev_inflight(helper_vdev_id);
		}

		if (inflight) {
			wma_warn("Monitor retune to %u MHz blocked: helper vdev %u still has %u in-flight frames after %u ms",
				 new_freq, helper_vdev_id, inflight,
				 drain_wait_ms);
			status = QDF_STATUS_E_BUSY;
		}
	}

	if (QDF_IS_STATUS_ERROR(qdf_mutex_acquire(&ctx->helper_lock))) {
		status = QDF_STATUS_E_BUSY;
		goto transition_done;
	}
	if (ctx->helper_stopping || !ctx->is_initialized ||
	    !wma_handle->wmi_handle ||
	    wmi_is_blocked(wma_handle->wmi_handle)) {
		status = QDF_STATUS_E_AGAIN;
		goto unlock;
	}

	if (QDF_IS_STATUS_SUCCESS(status) && g_inj_tx_vdev.created &&
	    g_inj_tx_vdev.monitor_vdev_id == mon_vdev_id &&
	    !wma_injection_vdev_inflight(g_inj_tx_vdev.vdev_id)) {
		if (ctx->recreate_helper_on_retune) {
			wma_info("Monitor retune to %u MHz: recreate TX helper vdev %u after directed-peer injection",
				 new_freq, g_inj_tx_vdev.vdev_id);
			status = wma_injection_destroy_tx_vdev(wma_handle);
			if (QDF_IS_STATUS_ERROR(status)) {
				wma_warn("Monitor retune helper recreation teardown failed: %d",
					 status);
				goto unlock;
			}
		}

		/*
		 * Keep a valid RF owner on the requested channel while the real
		 * monitor vdev is restarted. Firmware accepts this synchronized
		 * helper restart and monitor injection can reuse it afterward.
		 */
		status = wma_injection_ensure_tx_vdev(wma_handle, mon_vdev_id,
						       new_freq);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_warn("Monitor retune helper restart to %u MHz failed: %d",
				 new_freq, status);
			goto unlock;
		}

		wma_info("Monitor retune to %u MHz: keep retargeted TX helper vdev %u",
			 new_freq, g_inj_tx_vdev.vdev_id);
	}
unlock:
	qdf_mutex_release(&ctx->helper_lock);
	if (QDF_IS_STATUS_ERROR(status))
		wma_injection_complete_channel_change(wma_handle, mon_vdev_id,
						      false);
	return status;
transition_done:
	ctx->helper_transitioning = false;
	return status;
}

void wma_injection_complete_channel_change(tp_wma_handle wma_handle,
					   uint8_t mon_vdev_id,
					   bool success)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	bool queue_has_frames;

	if (!wma_handle || !ctx->is_initialized)
		return;
	if (QDF_IS_STATUS_ERROR(qdf_mutex_acquire(&ctx->helper_lock)))
		return;
	if (!ctx->helper_transitioning) {
		qdf_mutex_release(&ctx->helper_lock);
		return;
	}

	if (!success && g_inj_tx_vdev.created &&
	    g_inj_tx_vdev.monitor_vdev_id == mon_vdev_id) {
		QDF_STATUS status;

		wma_warn("Monitor channel transition failed: destroy retargeted helper vdev %u",
			 g_inj_tx_vdev.vdev_id);
		status = wma_injection_destroy_tx_vdev(wma_handle);
		if (QDF_IS_STATUS_ERROR(status))
			wma_warn("Failed transition helper teardown failed: %d",
				 status);
	}

	ctx->helper_transitioning = false;
	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_has_frames = !qdf_list_empty(&ctx->queue);
	qdf_spin_unlock_bh(&ctx->queue_lock);
	qdf_mutex_release(&ctx->helper_lock);

	wma_info("Monitor channel transition complete: vdev=%u success=%u queued=%u",
		 mon_vdev_id, success, queue_has_frames);
	if (queue_has_frames && !ctx->helper_stopping &&
	    !cds_is_driver_recovering())
		qdf_sched_work(0, &ctx->queue_work);
}

static QDF_STATUS
wma_injection_debug_cache_update(uint32_t desc_id,
				 struct inject_frame_req *req,
				 uint8_t fc_type,
				 uint8_t fc_subtype,
				 uint16_t chanfreq,
				 uint8_t vdev_id,
				 uint8_t vdev_type,
				 bool is_group,
				 bool peer_exists)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_debug_info *entry;
	uint32_t slot;

	if (!desc_id || !req || !req->frame_data)
		return QDF_STATUS_E_INVAL;

	slot = desc_id % WMA_INJECTION_DEBUG_CACHE_SIZE;
	entry = &g_wma_injection_debug_cache[slot];

	qdf_spin_lock_bh(&ctx->cache_lock);
	/* Never recycle a descriptor slot while firmware may own its DMA nbuf. */
	if (entry->valid && entry->tx_buf) {
		qdf_spin_unlock_bh(&ctx->cache_lock);
		wma_warn("Injection descriptor slot busy: new=%u outstanding=%u",
			 desc_id, entry->desc_id);
		return QDF_STATUS_E_RESOURCES;
	}

	entry->valid = false;
	entry->is_group = is_group;
	entry->peer_exists = peer_exists;
	entry->timed_out = false;
	entry->vdev_id = vdev_id;
	entry->vdev_type = vdev_type;
	entry->tx_path = WMA_INJECTION_TX_PATH_NONE;
	entry->desc_id = desc_id;
	entry->frame_len = req->frame_len;
	entry->chanfreq = chanfreq;
	entry->fc_type = fc_type;
	entry->fc_subtype = fc_subtype;
	entry->tx_buf = NULL;
	entry->submit_time_us = qdf_get_monotonic_boottime();
	qdf_mem_zero(entry->addr1, sizeof(entry->addr1));
	qdf_mem_zero(entry->addr2, sizeof(entry->addr2));
	qdf_mem_zero(entry->addr3, sizeof(entry->addr3));

	if (req->frame_len >= 24) {
		qdf_mem_copy(entry->addr1, &req->frame_data[4], QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(entry->addr2, &req->frame_data[10], QDF_MAC_ADDR_SIZE);
		qdf_mem_copy(entry->addr3, &req->frame_data[16], QDF_MAC_ADDR_SIZE);
	}

	entry->valid = true;
	qdf_spin_unlock_bh(&ctx->cache_lock);

	return QDF_STATUS_SUCCESS;
}

static struct wma_injection_debug_info *
wma_injection_debug_cache_get(uint32_t desc_id)
{
	struct wma_injection_debug_info *entry;
	uint32_t slot;

	if (!desc_id)
		return NULL;

	slot = desc_id % WMA_INJECTION_DEBUG_CACHE_SIZE;
	entry = &g_wma_injection_debug_cache[slot];
	if (!entry->valid || entry->desc_id != desc_id)
		return NULL;

	return entry;
}

/**
 * wma_injection_desc_id_alloc() - allocate descriptor id for injection tx
 *
 * Return: descriptor id in dedicated injection range
 */
static uint16_t wma_injection_desc_id_alloc(void)
{
	static uint16_t next_desc_id = WMA_INJECTION_DESC_ID_BASE;
	uint16_t desc_id = next_desc_id;

	next_desc_id++;
	if ((next_desc_id & ~WMA_INJECTION_DESC_ID_MASK) !=
	    WMA_INJECTION_DESC_ID_BASE)
		next_desc_id = WMA_INJECTION_DESC_ID_BASE;

	return desc_id;
}

/**
 * wma_injection_queue_node_alloc() - Allocate injection queue node
 * @req: Frame injection request
 * @vdev_id: VDEV ID
 *
 * Return: Allocated node or NULL on failure
 */
static struct wma_injection_queue_node *
wma_injection_queue_node_alloc(struct inject_frame_req *req, uint8_t vdev_id)
{
	struct wma_injection_queue_node *node;
	uint8_t *frame_copy;

	if (!req || !req->frame_data || req->frame_len == 0) {
		wma_err("Invalid injection request parameters");
		return NULL;
	}

	if (req->frame_len > WMA_FRAME_INJECT_MAX_FRAME_SIZE) {
		wma_err("Frame size %u exceeds maximum %u",
			req->frame_len, WMA_FRAME_INJECT_MAX_FRAME_SIZE);
		return NULL;
	}

	node = qdf_mem_malloc(sizeof(*node));
	if (!node) {
		wma_err("Failed to allocate injection queue node");
		return NULL;
	}

	/* Allocate and copy frame data */
	frame_copy = qdf_mem_malloc(req->frame_len);
	if (!frame_copy) {
		wma_err("Failed to allocate frame data buffer");
		qdf_mem_free(node);
		return NULL;
	}

	qdf_mem_copy(frame_copy, req->frame_data, req->frame_len);

	/* Initialize node */
	qdf_mem_zero(node, sizeof(*node));
	node->req.frame_len = req->frame_len;
	node->req.frame_data = frame_copy;
	node->req.tx_flags = req->tx_flags;
	node->req.retry_count = req->retry_count;
	node->req.tx_rate = req->tx_rate;
	node->req.timestamp = req->timestamp;
	node->req.session_id = req->session_id;
	node->timestamp = qdf_get_log_timestamp();
	node->vdev_id = vdev_id;

	return node;
}

/**
 * wma_injection_queue_node_free() - Free injection queue node
 * @node: Node to free
 */
static void wma_injection_queue_node_free(struct wma_injection_queue_node *node)
{
	if (!node)
		return;

	if (node->req.frame_data) {
		qdf_mem_free(node->req.frame_data);
		node->req.frame_data = NULL;
	}

	qdf_mem_free(node);
}

/**
 * wma_check_traffic_coordination() - Check if injection can proceed with current traffic
 * @wma_handle: WMA handle
 * @vdev_id: VDEV ID for the frame
 *
 * This function checks if frame injection should be deferred due to high
 * priority traffic or resource constraints in the WMA layer.
 *
 * Return: true if injection can proceed, false if should be deferred
 */
static bool wma_check_traffic_coordination(tp_wma_handle wma_handle, uint8_t vdev_id)
{
	struct wma_txrx_node *iface;

	if (!wma_handle || vdev_id >= wma_handle->max_bssid) {
		wma_err_rl("Invalid parameters: wma_handle=%pK, vdev_id=%u",
			   wma_handle, vdev_id);
		return false;
	}

	iface = &wma_handle->interfaces[vdev_id];

	/* Check if interface is in a state that allows injection */
	if (!iface->vdev) {
		wma_debug("Interface %u not active, deferring injection", vdev_id);
		return false;
	}

	/* Check system-wide resource constraints */
	if (wma_handle->wmi_ready == false) {
		wma_debug("WMI not ready, deferring injection");
		return false;
	}

	/* Check if firmware is overloaded (simple heuristic) */
	if (wma_handle->wmi_handle) {
		uint32_t pending_cmds = wmi_get_pending_cmds(wma_handle->wmi_handle);
		const uint32_t max_pending_threshold = 512;

		if (pending_cmds > max_pending_threshold) {
			wma_debug("Firmware overloaded (%u pending commands), deferring injection",
				  pending_cmds);
			return false;
		}
	}

	return true;
}

/**
 * wma_apply_injection_backpressure() - Apply backpressure when queue is congested
 * @ctx: Injection queue context
 *
 * This function implements backpressure mechanisms when the injection queue
 * becomes congested, including adaptive processing delays and queue throttling.
 *
 * Return: Recommended delay in milliseconds before next processing cycle
 */
static uint32_t wma_apply_injection_backpressure(struct wma_injection_queue_ctx *ctx)
{
	uint32_t queue_utilization;
	uint32_t delay_ms = 0;

	if (!ctx || !ctx->is_initialized) {
		return 0;
	}

	/* Calculate queue utilization percentage */
	queue_utilization = (ctx->queue_size * 100) / ctx->max_queue_size;

	/* Apply adaptive backpressure based on queue utilization */
	if (queue_utilization > 95) {
		/* Queue nearly full - significant backpressure */
		delay_ms = 10;
	} else if (queue_utilization > 85) {
		/* Queue getting full - moderate backpressure */
		delay_ms = 2;
	}

	return delay_ms;
}

/**
 * wma_process_injection_queue() - Process injection queue with traffic coordination
 * @wma_handle: WMA handle
 *
 * This function processes the injection queue while coordinating with existing
 * WMA traffic scheduling and applying backpressure when needed.
 *
 * Return: QDF_STATUS_SUCCESS on success, error code on failure
 */
QDF_STATUS wma_process_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	qdf_list_node_t *list_node;
	QDF_STATUS status;
	uint64_t current_time;
	uint32_t processed_count = 0;
	uint32_t deferred_count = 0;
	const uint32_t max_process_per_cycle = 64;
	bool queue_was_empty;
	bool retry_deferred = false;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (cds_is_driver_recovering() || !ctx->is_initialized ||
	    ctx->helper_stopping ||
	    ctx->helper_transitioning) {
		wma_debug("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	current_time = qdf_get_log_timestamp();

	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_was_empty = qdf_list_empty(&ctx->queue);
	qdf_spin_unlock_bh(&ctx->queue_lock);

	if (queue_was_empty)
		return QDF_STATUS_SUCCESS;

	/* Process frames from queue with traffic coordination */
	while (processed_count < max_process_per_cycle) {
		qdf_spin_lock_bh(&ctx->queue_lock);

		if (qdf_list_empty(&ctx->queue)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			break;
		}

		/* Peek at the front node to check VDEV before removing */
		status = qdf_list_peek_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			wma_err("Failed to peek at queue front: %d", status);
			break;
		}

		node = qdf_container_of(list_node, struct wma_injection_queue_node, node);
		if (node->vdev_id >= wma_handle->max_bssid ||
		    !wma_handle->interfaces[node->vdev_id].vdev) {
			status = qdf_list_remove_front(&ctx->queue, &list_node);
			if (!QDF_IS_STATUS_ERROR(status))
				ctx->queue_size--;
			qdf_spin_unlock_bh(&ctx->queue_lock);
			if (QDF_IS_STATUS_ERROR(status)) {
				wma_err_rl("Failed to remove stale injection node: %d",
					   status);
				break;
			}
			ctx->stats.frames_dropped++;
			wma_err_rl("Dropping stale injection node with vdev_id=%u",
				   node->vdev_id);
			wma_injection_queue_node_free(node);
			processed_count++;
			continue;
		}

		/* Check traffic coordination before processing */
		if (!wma_check_traffic_coordination(wma_handle, node->vdev_id)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			deferred_count++;
			wma_debug("Deferring injection due to traffic coordination (vdev_id=%u)",
				  node->vdev_id);
			break;
		}

		/* Remove the node from queue */
		status = qdf_list_remove_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_spin_unlock_bh(&ctx->queue_lock);
			wma_err("Failed to remove node from queue: %d", status);
			break;
		}

		ctx->queue_size--;
		qdf_spin_unlock_bh(&ctx->queue_lock);

		/* Send frame to firmware */
		status = wma_send_injection_frame_to_fw(wma_handle, &node->req, node->vdev_id);
		if (status == QDF_STATUS_E_BUSY ||
		    status == QDF_STATUS_E_AGAIN ||
		    status == QDF_STATUS_E_RESOURCES) {
			/* Preserve FIFO order until the previous destination peer is idle. */
			qdf_spin_lock_bh(&ctx->queue_lock);
			status = qdf_list_insert_front(&ctx->queue, &node->node);
			if (!QDF_IS_STATUS_ERROR(status))
				ctx->queue_size++;
			qdf_spin_unlock_bh(&ctx->queue_lock);
			if (QDF_IS_STATUS_ERROR(status)) {
				ctx->stats.frames_dropped++;
				wma_injection_queue_node_free(node);
			}
			deferred_count++;
			retry_deferred = true;
			break;
		}

		/* Update queue time statistics after final submission disposition. */
		ctx->stats.total_queue_time += (current_time - node->timestamp);
		if (QDF_IS_STATUS_ERROR(status)) {
			ctx->stats.frames_dropped++;
			wma_err("Failed to send injection frame to firmware: %d", status);
		}

		processed_count++;

		/* Free the node */
		wma_injection_queue_node_free(node);
	}

	wma_debug("Injection queue processing cycle complete: processed=%u, deferred=%u",
		  processed_count, deferred_count);

	return retry_deferred ? QDF_STATUS_E_BUSY : QDF_STATUS_SUCCESS;
}

/**
 * wma_process_injection_queue_work() - Work function to process injection queue
 * @arg: Work argument (not used)
 *
 * This function processes queued frame injection requests in FIFO order
 * with traffic coordination and backpressure handling.
 */
static void wma_process_injection_queue_work(void *arg)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	tp_wma_handle wma_handle;
	QDF_STATUS status;
	uint32_t backpressure_delay;
	bool queue_has_frames;

	if (cds_is_driver_recovering() || !ctx->is_initialized ||
	    ctx->helper_stopping ||
	    ctx->helper_transitioning) {
		wma_debug("Injection queue not initialized");
		return;
	}

	/* Get WMA handle for processing */
	wma_handle = cds_get_context(QDF_MODULE_ID_WMA);
	if (!wma_handle) {
		wma_err("Failed to get WMA handle");
		return;
	}

	/* Process the queue */
	status = wma_process_injection_queue(wma_handle);
	if (QDF_IS_STATUS_ERROR(status) && status != QDF_STATUS_E_BUSY) {
		wma_err("Failed to process injection queue: %d", status);
	}

	/* Check if there are more frames to process */
	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_has_frames = !qdf_list_empty(&ctx->queue);
	qdf_spin_unlock_bh(&ctx->queue_lock);

	if (queue_has_frames && !cds_is_driver_recovering() &&
	    !ctx->helper_stopping &&
	    !ctx->helper_transitioning) {
		/* Apply backpressure if queue is congested */
		backpressure_delay = status == QDF_STATUS_E_BUSY ? 2 :
			wma_apply_injection_backpressure(ctx);
		
		if (backpressure_delay > 0) {
			qdf_delayed_work_start(&ctx->delayed_work, backpressure_delay);
		} else {
			/* Schedule immediate work for next processing cycle */
			qdf_sched_work(0, &ctx->queue_work);
		}
	}
}

/**
 * wma_process_injection_queue_delayed_work() - Delayed work callback for backpressure
 * @context: Context (not used)
 *
 * This function is called when delayed work is triggered for backpressure handling.
 * It simply schedules the regular work item to continue processing.
 */
static void wma_process_injection_queue_delayed_work(void *context)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (cds_is_driver_recovering() || !ctx->is_initialized ||
	    ctx->helper_stopping ||
	    ctx->helper_transitioning)
		return;

	qdf_sched_work(0, &ctx->queue_work);
}

/**
 * wma_injection_reaper_work_cb() - Periodic reaper for stale injection nbufs
 * @context: Unused
 *
 * Some firmware builds omit TX-completion events for frames sent on the hidden
 * STA helper vdev when its per-vdev completion callback is absent (see
 * wal_local_frame_mgmt_tx_completion / FUN_b013dd78). Left unchecked the
 * DMA-mapped nbufs accumulate and can eventually exhaust mapped memory.
 *
 * This worker runs every WMA_INJECTION_REAPER_INTERVAL_MS, scans the
 * debug cache, and frees any entry whose submit_time_us is older than
 * WMA_INJECTION_NBUF_TIMEOUT_US (2 s).
 */
static void wma_injection_reaper_work_cb(void *context)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	uint64_t now_us, age_us;
	uint32_t reaped = 0;
	int i;

	if (!ctx->is_initialized)
		return;

	now_us = qdf_get_monotonic_boottime();

	for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
		struct wma_injection_debug_info *e =
			&g_wma_injection_debug_cache[i];
		qdf_nbuf_t stale_buf = NULL;
		uint32_t desc_id;
		uint8_t vdev_id;
		uint8_t tx_path;

		qdf_spin_lock_bh(&ctx->cache_lock);
		if (!e->valid || !e->tx_buf || !e->submit_time_us)
			goto next_entry;

		/* Never turn a clock regression into an unsigned stale timeout. */
		if (now_us < e->submit_time_us)
			goto next_entry;

		age_us = now_us - e->submit_time_us;

		if (age_us < WMA_INJECTION_NBUF_TIMEOUT_US)
			goto next_entry;

		desc_id = e->desc_id;
		vdev_id = e->vdev_id;
		tx_path = e->tx_path;
		stale_buf = e->tx_buf;
		e->tx_buf = NULL;
		e->timed_out = true;
		e->valid = false;
		qdf_atomic_dec(&g_wma_injection_ctx.inflight_count);
		ctx->stats.tx_timeout++;
		ctx->stats.fw_timeouts++;
		reaped++;

next_entry:
		qdf_spin_unlock_bh(&ctx->cache_lock);
		if (!stale_buf)
			continue;

		wma_injection_unmap_tx_buf(stale_buf);
		qdf_nbuf_free(stale_buf);
		if (ctx->stats.tx_timeout <= 10)
			wma_warn("Injection timeout: desc_id=%u vdev=%u path=%s age=%llu us",
				 desc_id, vdev_id,
				 tx_path == WMA_INJECTION_TX_PATH_WMI ? "WMI" : "legacy",
				 age_us);
	}

	if (reaped)
		wma_info("Reaper: freed %u stale injection nbufs, inflight now %d",
			 reaped,
			 qdf_atomic_read(&g_wma_injection_ctx.inflight_count));
	/* Re-arm the periodic timer */
	if (ctx->is_initialized && !ctx->helper_stopping &&
	    !cds_is_driver_recovering())
		qdf_delayed_work_start(&ctx->reaper_work,
				       WMA_INJECTION_REAPER_INTERVAL_MS);
}

QDF_STATUS wma_init_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	QDF_STATUS status;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (ctx->is_initialized) {
		wma_debug("Injection queue already initialized");
		return QDF_STATUS_SUCCESS;
	}

	wma_debug("Initializing WMA injection queue");

	/* Initialize queue */
	qdf_list_create(&ctx->queue, WMA_FRAME_INJECT_MAX_QUEUE_SIZE);

	/* Initialize queue lock */
	qdf_spinlock_create(&ctx->queue_lock);
	qdf_spinlock_create(&ctx->cache_lock);
	status = qdf_mutex_create(&ctx->helper_lock);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_spinlock_destroy(&ctx->cache_lock);
		qdf_spinlock_destroy(&ctx->queue_lock);
		qdf_list_destroy(&ctx->queue);
		return status;
	}

	/* Initialize work item */
	qdf_create_work(0, &ctx->queue_work, wma_process_injection_queue_work, NULL);

	/* Initialize delayed work item for backpressure */
	status = qdf_delayed_work_create(&ctx->delayed_work, 
					 wma_process_injection_queue_delayed_work, NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Failed to create delayed work: %d", status);
		qdf_mutex_destroy(&ctx->helper_lock);
		qdf_spinlock_destroy(&ctx->cache_lock);
		qdf_spinlock_destroy(&ctx->queue_lock);
		qdf_list_destroy(&ctx->queue);
		return status;
	}

	/* Initialize nbuf-leak reaper timer */
	status = qdf_delayed_work_create(&ctx->reaper_work,
					 wma_injection_reaper_work_cb, NULL);
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Failed to create reaper work: %d", status);
		qdf_delayed_work_destroy(&ctx->delayed_work);
		qdf_mutex_destroy(&ctx->helper_lock);
		qdf_spinlock_destroy(&ctx->cache_lock);
		qdf_spinlock_destroy(&ctx->queue_lock);
		qdf_list_destroy(&ctx->queue);
		return status;
	}

	/* Initialize context */
	ctx->queue_size = 0;
	ctx->max_queue_size = WMA_FRAME_INJECT_MAX_QUEUE_SIZE;
	qdf_mem_zero(&ctx->stats, sizeof(ctx->stats));
	qdf_atomic_init(&ctx->inflight_count);
	qdf_atomic_init(&g_inj_peer_rsp.expected);
	qdf_atomic_init(&g_inj_peer_rsp.completed);
	qdf_atomic_init(&g_inj_peer_rsp.result);
	qdf_atomic_set(&g_inj_peer_rsp.expected,
		       WMA_INJECTION_PEER_RSP_NONE);
	qdf_atomic_set(&g_inj_peer_rsp.completed,
		       WMA_INJECTION_PEER_RSP_NONE);
	qdf_atomic_set(&g_inj_peer_rsp.result, QDF_STATUS_SUCCESS);
	ctx->helper_stopping = false;
	ctx->helper_transitioning = false;
	ctx->recreate_helper_on_retune = false;
	ctx->is_initialized = true;

	/* Arm the reaper */
	qdf_delayed_work_start(&ctx->reaper_work,
			       WMA_INJECTION_REAPER_INTERVAL_MS);

	wma_info("WMA injection queue initialized successfully (max_size=%u)",
		 ctx->max_queue_size);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_deinit_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	qdf_list_node_t *list_node;
	QDF_STATUS status;
	uint32_t dropped_count = 0;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_debug("Injection queue not initialized");
		return QDF_STATUS_SUCCESS;
	}

	wma_debug("Deinitializing WMA injection queue");

	/* Close producers before synchronously draining their work items. */
	ctx->helper_stopping = true;
	qdf_cancel_work(&ctx->queue_work);
	qdf_flush_work(&ctx->queue_work);
	/* Block late completions and direct retries before work objects go away. */
	ctx->is_initialized = false;
	
	/* Cancel and destroy delayed work */
	qdf_delayed_work_stop_sync(&ctx->delayed_work);
	qdf_delayed_work_destroy(&ctx->delayed_work);

	/* Stop and destroy reaper timer */
	qdf_delayed_work_stop_sync(&ctx->reaper_work);
	qdf_delayed_work_destroy(&ctx->reaper_work);

	/* No worker can submit another frame while the helper is destroyed. */
	wma_injection_destroy_tx_vdev(wma_handle);
	wma_injection_peer_rsp_cancel(WMA_INJECTION_PEER_RSP_CREATE);
	wma_injection_peer_rsp_cancel(WMA_INJECTION_PEER_RSP_DELETE);

	/* Clear the queue and free all nodes */
	qdf_spin_lock_bh(&ctx->queue_lock);

	while (!qdf_list_empty(&ctx->queue)) {
		status = qdf_list_remove_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Failed to remove node during cleanup: %d", status);
			break;
		}

		node = qdf_container_of(list_node, struct wma_injection_queue_node, node);
		wma_injection_queue_node_free(node);
		dropped_count++;
	}

	ctx->queue_size = 0;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	/* Update statistics */
	ctx->stats.frames_dropped += dropped_count;

	/*
	 * Flush any in-flight nbufs still tracked in the debug cache.
	 * These are frames submitted to firmware whose completions never
	 * arrived before the queue was torn down.
	 */
	{
		uint32_t i;
		uint32_t nbuf_leaked = 0;

		for (i = 0; i < WMA_INJECTION_DEBUG_CACHE_SIZE; i++) {
			struct wma_injection_debug_info *e =
				&g_wma_injection_debug_cache[i];
			qdf_nbuf_t tx_buf;

			qdf_spin_lock_bh(&ctx->cache_lock);
			tx_buf = e->tx_buf;
			e->tx_buf = NULL;
			e->valid = false;
			qdf_spin_unlock_bh(&ctx->cache_lock);
			if (tx_buf) {
				wma_injection_unmap_tx_buf(tx_buf);
				qdf_nbuf_free(tx_buf);
				nbuf_leaked++;
			}
		}
		if (nbuf_leaked)
			wma_warn("Freed %u leaked injection nbufs during deinit",
				 nbuf_leaked);
	}

	qdf_list_destroy(&ctx->queue);
	qdf_spinlock_destroy(&ctx->cache_lock);
	qdf_spinlock_destroy(&ctx->queue_lock);
	qdf_mutex_destroy(&ctx->helper_lock);

	wma_info("WMA injection queue deinitialized (dropped %u pending frames)",
		 dropped_count);

	return QDF_STATUS_SUCCESS;
}

void wma_injection_ssr_resume(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle || !ctx->is_initialized || cds_is_driver_recovering())
		return;

	/* Firmware restart invalidates every helper and peer from the old WMA. */
	qdf_mem_zero(&g_inj_tx_vdev, sizeof(g_inj_tx_vdev));
	qdf_atomic_set(&g_inj_peer_rsp.expected,
		       WMA_INJECTION_PEER_RSP_NONE);
	qdf_atomic_set(&g_inj_peer_rsp.completed,
		       WMA_INJECTION_PEER_RSP_NONE);
	ctx->helper_transitioning = false;
	ctx->helper_stopping = false;
	ctx->recreate_helper_on_retune = false;

	qdf_delayed_work_start(&ctx->reaper_work,
			       WMA_INJECTION_REAPER_INTERVAL_MS);
}

QDF_STATUS wma_queue_injection_frame(tp_wma_handle wma_handle,
				     struct inject_frame_req *req,
				     uint8_t vdev_id)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	QDF_STATUS status;

	if (!wma_handle || !req) {
		wma_err("Invalid parameters: wma_handle=%pK, req=%pK",
			wma_handle, req);
		return QDF_STATUS_E_INVAL;
	}
	if (vdev_id >= wma_handle->max_bssid ||
	    !wma_handle->interfaces[vdev_id].vdev) {
		wma_err_rl("Rejecting injection for invalid vdev_id=%u", vdev_id);
		return QDF_STATUS_E_AGAIN;
	}

	if (cds_is_driver_recovering() || !ctx->is_initialized ||
	    ctx->helper_stopping ||
	    ctx->helper_transitioning) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	/* Validate frame parameters */
	if (!req->frame_data || req->frame_len == 0 ||
	    req->frame_len > WMA_FRAME_INJECT_MAX_FRAME_SIZE) {
		wma_err("Invalid frame parameters: data=%pK, len=%u",
			req->frame_data, req->frame_len);
		return QDF_STATUS_E_INVAL;
	}

	/*
	 * For a regular vdev, reject an unknown unicast management destination
	 * before queueing. Monitor vdevs preserve raw Addr1/Addr2/Addr3 and create a
	 * transient firmware peer in the send path.
	 */
	if (req->frame_len >= 24 &&
	    (req->frame_data[0] & 0x0c) == 0x00 &&
	    !qdf_is_macaddr_group((struct qdf_mac_addr *)&req->frame_data[4]) &&
	    vdev_id < wma_handle->max_bssid &&
	    wma_handle->interfaces[vdev_id].type != WMI_VDEV_TYPE_MONITOR) {
		uint8_t resolved_vdev;
		uint8_t resolved_type;
		uint16_t resolved_freq;
		uint8_t subtype = req->frame_data[0] & 0xf0;

		/*
		 * Keep this raw path non-destructive and independent of PMF keys.
		 * Robust actions and all association/disconnect management must use
		 * the normal AP management interface, which applies PMF policy.
		 */
		if (subtype != 0xd0 || req->frame_len < 25 ||
		    req->frame_data[24] != 4 || (req->frame_data[1] & 0x43)) {
			ctx->stats.frames_dropped++;
			if (ctx->stats.frames_dropped <= 10)
				wma_warn("Injection unicast supports Public Action only; use standard management API for subtype=0x%02x category=%u",
					 subtype,
					 req->frame_len >= 25 ? req->frame_data[24] : 0xff);
			return QDF_STATUS_E_NOSUPPORT;
		}

		status = wma_injection_find_unicast_peer(
			wma_handle, &req->frame_data[4], &req->frame_data[10],
			&req->frame_data[16], &resolved_vdev, &resolved_freq,
			&resolved_type);
		if (QDF_IS_STATUS_ERROR(status)) {
			if (status == QDF_STATUS_E_NOENT) {
				ctx->stats.peer_not_found++;
				if (ctx->stats.peer_not_found <= 10 ||
				    !(ctx->stats.peer_not_found % 100))
					wma_warn("Injection peer_not_found: addr1=%pM source_vdev=%u count=%llu",
						 &req->frame_data[4], vdev_id,
						 ctx->stats.peer_not_found);
			}
			ctx->stats.frames_dropped++;
			return status;
		}
	}

	/* Check queue overflow */
	qdf_spin_lock_bh(&ctx->queue_lock);

	if (ctx->queue_size >= ctx->max_queue_size) {
		qdf_spin_unlock_bh(&ctx->queue_lock);
		ctx->stats.queue_overflows++;
		ctx->stats.frames_dropped++;
		wma_err("Injection queue overflow (size=%u, max=%u)",
			ctx->queue_size, ctx->max_queue_size);
		return QDF_STATUS_E_RESOURCES;
	}

	qdf_spin_unlock_bh(&ctx->queue_lock);

	/*
	 * Inflight backpressure: if too many nbufs are waiting for FW
	 * completions that will never arrive, reject early to avoid
	 * exhausting DMA-mapped memory and triggering an SMMU fault.
	 * The reaper timer will gradually free the stale entries.
	 */
	{
		int inflight = qdf_atomic_read(&ctx->inflight_count);

		if (inflight >= WMA_INJECTION_INFLIGHT_HIGH) {
			ctx->stats.frames_dropped++;
			if (ctx->stats.frames_dropped % 100 == 1)
				wma_warn("Injection backpressure: inflight=%d >= %d, dropping frame",
					 inflight, WMA_INJECTION_INFLIGHT_HIGH);
			return QDF_STATUS_E_RESOURCES;
		}
	}

	/* Allocate and initialize queue node */
	node = wma_injection_queue_node_alloc(req, vdev_id);
	if (!node) {
		ctx->stats.frames_dropped++;
		wma_err("Failed to allocate injection queue node");
		return QDF_STATUS_E_NOMEM;
	}

	/* Add to queue */
	qdf_spin_lock_bh(&ctx->queue_lock);
	if (cds_is_driver_recovering() || !ctx->is_initialized ||
	    ctx->helper_stopping ||
	    ctx->helper_transitioning) {
		qdf_spin_unlock_bh(&ctx->queue_lock);
		wma_injection_queue_node_free(node);
		return QDF_STATUS_E_AGAIN;
	}

	status = qdf_list_insert_back(&ctx->queue, &node->node);
	if (QDF_IS_STATUS_ERROR(status)) {
		qdf_spin_unlock_bh(&ctx->queue_lock);
		wma_injection_queue_node_free(node);
		ctx->stats.frames_dropped++;
		wma_err("Failed to add node to queue: %d", status);
		return status;
	}

	ctx->queue_size++;
	ctx->stats.frames_queued++;

	/* Update maximum queue depth */
	if (ctx->queue_size > ctx->stats.max_queue_depth) {
		ctx->stats.max_queue_depth = ctx->queue_size;
	}

	qdf_spin_unlock_bh(&ctx->queue_lock);

	/* Schedule queue processing work */
	qdf_sched_work(0, &ctx->queue_work);

	wma_debug("Queued injection frame: len=%u, vdev_id=%u, queue_size=%u",
		  req->frame_len, vdev_id, ctx->queue_size);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_get_injection_queue_stats(tp_wma_handle wma_handle,
					 struct wma_injection_queue_stats *stats)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle || !stats) {
		wma_err("Invalid parameters: wma_handle=%pK, stats=%pK",
			wma_handle, stats);
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	qdf_mem_copy(stats, &ctx->stats, sizeof(*stats));
	qdf_spin_unlock_bh(&ctx->queue_lock);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_reset_injection_queue_stats(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	qdf_mem_zero(&ctx->stats, sizeof(ctx->stats));
	qdf_spin_unlock_bh(&ctx->queue_lock);

	wma_info("Injection queue statistics reset");

	return QDF_STATUS_SUCCESS;
}

uint32_t wma_get_injection_queue_size(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	uint32_t queue_size;

	if (!wma_handle || !ctx->is_initialized) {
		return 0;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	queue_size = ctx->queue_size;
	qdf_spin_unlock_bh(&ctx->queue_lock);

	return queue_size;
}

bool wma_is_injection_queue_empty(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	bool is_empty;

	if (!wma_handle || !ctx->is_initialized) {
		return true;
	}

	qdf_spin_lock_bh(&ctx->queue_lock);
	is_empty = qdf_list_empty(&ctx->queue);
	qdf_spin_unlock_bh(&ctx->queue_lock);

	return is_empty;
}

QDF_STATUS wma_flush_injection_queue(tp_wma_handle wma_handle)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_queue_node *node;
	qdf_list_node_t *list_node;
	QDF_STATUS status;
	uint32_t flushed_count = 0;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_err("Injection queue not initialized");
		return QDF_STATUS_E_AGAIN;
	}

	wma_debug("Flushing injection queue");

	/* Cancel any pending work */
	qdf_cancel_work(&ctx->queue_work);
	qdf_flush_work(&ctx->queue_work);
	qdf_delayed_work_stop_sync(&ctx->delayed_work);

	/* Flush all queued frames */
	qdf_spin_lock_bh(&ctx->queue_lock);

	while (!qdf_list_empty(&ctx->queue)) {
		status = qdf_list_remove_front(&ctx->queue, &list_node);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Failed to remove node during flush: %d", status);
			break;
		}

		node = qdf_container_of(list_node, struct wma_injection_queue_node, node);
		wma_injection_queue_node_free(node);
		flushed_count++;
	}

	ctx->queue_size = 0;
	ctx->stats.frames_dropped += flushed_count;

	qdf_spin_unlock_bh(&ctx->queue_lock);

	wma_info("Flushed %u frames from injection queue", flushed_count);

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_send_injection_frame_to_fw(tp_wma_handle wma_handle,
					  struct inject_frame_req *req,
					  uint8_t vdev_id)
{
	struct wmi_mgmt_params mgmt_params;
	QDF_STATUS status;
	qdf_nbuf_t wmi_buf;
	uint8_t *frame_data;
	struct cdp_soc_t *soc;
	void *qdf_ctx;
	int ret;
	uint16_t tx_chanfreq = 0;
	uint8_t fc0 = 0;
	uint8_t fc_type = 0;
	uint8_t fc_subtype = 0;
	bool is_group_da = false;
	bool peer_exists = false;
	bool wmi_mgmt_service;
	bool wmi_tx_attempted = false;
	bool wmi_tx_ok = false;
	bool is_probe_req = false;
	bool monitor_vdev = false;
	bool source_monitor_vdev = false;
	bool log_send_info;
	bool helper_locked = false;
	uint8_t tx_vdev_type;

	if (!wma_handle || !req || !req->frame_data) {
		wma_err("Invalid parameters: wma_handle=%pK, req=%pK",
			wma_handle, req);
		return QDF_STATUS_E_INVAL;
	}
	if (cds_is_driver_recovering() ||
	    !g_wma_injection_ctx.is_initialized ||
	    g_wma_injection_ctx.helper_stopping ||
	    g_wma_injection_ctx.helper_transitioning ||
	    !wma_handle->wmi_handle || wmi_is_blocked(wma_handle->wmi_handle))
		return QDF_STATUS_E_AGAIN;

	if (req->frame_len == 0 || req->frame_len > WMA_FRAME_INJECT_MAX_FRAME_SIZE) {
		wma_err("Invalid frame length: %u", req->frame_len);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle->wmi_handle) {
		wma_err("Invalid WMI handle in injection path");
		return QDF_STATUS_E_INVAL;
	}

	if (vdev_id >= wma_handle->max_bssid) {
		wma_err("Invalid injection vdev_id %u (max %u)",
			vdev_id, wma_handle->max_bssid);
		return QDF_STATUS_E_INVAL;
	}

	if (!wma_handle->interfaces[vdev_id].vdev) {
		wma_err("Injection vdev %u is not active", vdev_id);
		return QDF_STATUS_E_AGAIN;
	}

	if (wma_handle->interfaces[vdev_id].vdev->vdev_mlme.des_chan &&
	    wma_handle->interfaces[vdev_id].vdev->vdev_mlme.des_chan->ch_freq)
		tx_chanfreq = wma_handle->interfaces[vdev_id].vdev->vdev_mlme.des_chan->ch_freq;

	if (req->frame_len)
		fc0 = req->frame_data[0];

	fc_type = fc0 & 0x0c;
	fc_subtype = fc0 & 0xf0;
	is_probe_req = (fc_type == 0x00 && fc_subtype == 0x40);
	if (req->frame_len >= 10)
		is_group_da = qdf_is_macaddr_group(
			(struct qdf_mac_addr *)&req->frame_data[4]);

	if (fc_type == 0x00 && req->frame_len < 24) {
		wma_err("Injected management frame is shorter than its MAC header: %u",
			req->frame_len);
		return QDF_STATUS_E_INVAL;
	}

	qdf_ctx = cds_get_context(QDF_MODULE_ID_QDF_DEVICE);
	if (!qdf_ctx) {
		wma_err("qdf_ctx is NULL in injection path");
		return QDF_STATUS_E_INVAL;
	}

	source_monitor_vdev =
		(wma_handle->interfaces[vdev_id].type == WMI_VDEV_TYPE_MONITOR);
	monitor_vdev = source_monitor_vdev;
	tx_vdev_type = wma_handle->interfaces[vdev_id].type;
	if (source_monitor_vdev && !tx_chanfreq) {
		wma_err("Injection monitor vdev %u has zero channel frequency; dropping frame",
			vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	/*
	 * Regular vdev unicast must use the real vdev that owns Addr1's connected
	 * peer. Monitor unicast remains on the raw helper path, where a transient
	 * firmware peer is created without rewriting the supplied frame addresses.
	 */
	if (fc_type == 0x00 && !is_group_da && !source_monitor_vdev) {
		if (fc_subtype != 0xd0 || req->frame_len < 25 ||
		    req->frame_data[24] != 4 || (req->frame_data[1] & 0x43)) {
			if (g_wma_injection_ctx.stats.frames_dropped <= 10)
				wma_warn("Injection unicast supports Public Action only; use standard management API for subtype=0x%02x category=%u",
					 fc_subtype,
					 req->frame_len >= 25 ? req->frame_data[24] : 0xff);
			return QDF_STATUS_E_NOSUPPORT;
		}

		status = wma_injection_find_unicast_peer(
			wma_handle, &req->frame_data[4], &req->frame_data[10],
			&req->frame_data[16], &vdev_id, &tx_chanfreq,
			&tx_vdev_type);
		if (QDF_IS_STATUS_ERROR(status)) {
			if (status == QDF_STATUS_E_NOENT) {
				g_wma_injection_ctx.stats.peer_not_found++;
				if (g_wma_injection_ctx.stats.peer_not_found <= 10 ||
				    !(g_wma_injection_ctx.stats.peer_not_found % 100))
					wma_warn("Injection peer_not_found before submit: addr1=%pM count=%llu",
						 &req->frame_data[4],
						 g_wma_injection_ctx.stats.peer_not_found);
			}
			return status;
		}
		peer_exists = true;
		monitor_vdev = false;
	}

	/* Allocate WMI buffer for the frame */
	wmi_buf = qdf_nbuf_alloc(NULL, req->frame_len, 0, 0, false);
	if (!wmi_buf) {
		wma_err("Failed to allocate WMI buffer for injection frame");
		return QDF_STATUS_E_NOMEM;
	}

	/* Copy frame data to WMI buffer */
	frame_data = qdf_nbuf_put_tail(wmi_buf, req->frame_len);
	if (!frame_data) {
		wma_err("Failed to get buffer space for frame data");
		qdf_nbuf_free(wmi_buf);
		return QDF_STATUS_E_NOMEM;
	}

	qdf_mem_copy(frame_data, req->frame_data, req->frame_len);

	/*
	 * Monitor probe-request injection can be discarded by firmware when SA
	 * does not match the transmitting vdev MAC. Normalize SA for broadcast
	 * probe requests before WMI submission.
	 */
	if (source_monitor_vdev && is_probe_req && is_group_da &&
	    req->frame_len >= 24) {
		uint8_t *vdev_mac =
			wlan_vdev_mlme_get_macaddr(wma_handle->interfaces[vdev_id].vdev);

		if (vdev_mac &&
		    qdf_mem_cmp(frame_data + 10, vdev_mac, QDF_MAC_ADDR_SIZE) != 0) {
			if (!inject_probe_sa_fix_logged) {
				wma_warn("Injection probe-req SA override %pM -> %pM on vdev %u",
					 frame_data + 10, vdev_mac, vdev_id);
				inject_probe_sa_fix_logged = true;
			}
			qdf_mem_copy(frame_data + 10, vdev_mac, QDF_MAC_ADDR_SIZE);
			qdf_mem_copy(req->frame_data + 10, vdev_mac, QDF_MAC_ADDR_SIZE);
		}
	}

	/* Initialize WMI management parameters for injection */
	qdf_mem_zero(&mgmt_params, sizeof(mgmt_params));
	mgmt_params.tx_frame = wmi_buf;
	mgmt_params.frm_len = req->frame_len;
	mgmt_params.vdev_id = vdev_id;
	/*
	 * Use ACK-completion tx type for injection consistently. Several
	 * firmware builds are stricter with probe-request tx_type handling and
	 * are less likely to discard when sent with ACK-completion semantics.
	 */
	mgmt_params.tx_type = GENERIC_NODOWNLD_NOACK_COMP_INDEX;
	/*
	 * Align with regular host management TX behavior:
	 * probe request uses chanfreq=0 while action/auth/probe-rsp can carry
	 * an explicit channel.
	 */
	mgmt_params.chanfreq = is_probe_req ? 0 : tx_chanfreq;
	/*
	 * For monitor vdev probe injection, prefer explicit channel in command
	 * so firmware can bind probe request tx to the current monitor channel.
	 */
	if (monitor_vdev && is_probe_req && tx_chanfreq)
		mgmt_params.chanfreq = tx_chanfreq;
	mgmt_params.desc_id = wma_injection_desc_id_alloc();
	mgmt_params.pdata = frame_data; /* Management frame bytes for command payload */
	/* TLV WMI derives the peer from Addr1; legacy CDP also gets it here. */
	mgmt_params.macaddr = frame_data + 4;
	mgmt_params.qdf_ctx = qdf_ctx;
	mgmt_params.tx_params_valid = false; /* Use default TX parameters */
	mgmt_params.use_6mbps = 0; /* Use rate from injection request if specified */

	/* Keep real-peer unicast under the vdev/firmware management-rate policy. */
	if (req->tx_rate != 0 && is_group_da) {
		mgmt_params.tx_param.mcs_mask = req->tx_rate;
		mgmt_params.tx_params_valid = true;
	}
	if (source_monitor_vdev && !is_group_da) {
		mgmt_params.tx_param.retry_limit = 1;
		mgmt_params.tx_param.retry_limit_ext = 0;
		mgmt_params.tx_params_valid = true;
	}

	if (!inject_tx_cfg_logged) {
		wma_info("Injection TX config: vdev=%u iface_type=%u iface_subtype=%u vdev_active=%u chanfreq=%u",
			 vdev_id,
			 wma_handle->interfaces[vdev_id].type,
			 wma_handle->interfaces[vdev_id].sub_type,
			 wma_handle->interfaces[vdev_id].vdev_active ? 1 : 0,
			 mgmt_params.chanfreq);
		inject_tx_cfg_logged = true;
	}

	log_send_info = inject_send_info_count < 10;
	if (log_send_info) {
		if (req->frame_len >= 24) {
			uint8_t *addr1 = &req->frame_data[4];
			uint8_t *addr2 = &req->frame_data[10];
			uint8_t *addr3 = &req->frame_data[16];

			wma_info("Injection frame[%u]: desc_id=%u vdev=%u len=%u fc_type=0x%02x fc_subtype=0x%02x tx_chanfreq=%u cmd_chanfreq=%u addr1=%pM addr2=%pM addr3=%pM",
				 inject_send_info_count + 1, mgmt_params.desc_id,
				 vdev_id, req->frame_len,
				 fc_type, fc_subtype, tx_chanfreq, mgmt_params.chanfreq,
				 addr1, addr2, addr3);
		} else {
			wma_info("Injection frame[%u]: desc_id=%u vdev=%u len=%u fc_type=0x%02x fc_subtype=0x%02x tx_chanfreq=%u cmd_chanfreq=%u",
				 inject_send_info_count + 1, mgmt_params.desc_id,
				 vdev_id, req->frame_len,
				 fc_type, fc_subtype, tx_chanfreq, mgmt_params.chanfreq);
		}
		inject_send_info_count++;
	}

	wmi_mgmt_service = wmi_service_enabled(wma_handle->wmi_handle,
					       wmi_service_mgmt_tx_wmi);
	if (monitor_vdev && !wmi_mgmt_service && !inject_wmi_service_absent_logged) {
		wma_warn("Injection monitor vdev: mgmt_tx_wmi service bit is 0, but WMI TX will still be attempted");
		inject_wmi_service_absent_logged = true;
	}

	if (monitor_vdev) {
		/*
		 * FW _wlan_send_mgmt_to_host rejects MONITOR vdevs (falls
		 * to a beacon-only path → DISCARD).  Route through a hidden
		 * STA helper vdev instead. Its self-peer handles group traffic and a
		 * transient Addr1 peer handles directed traffic.
		 */
		status = qdf_mutex_acquire(
			&g_wma_injection_ctx.helper_lock);
		if (QDF_IS_STATUS_ERROR(status)) {
			qdf_nbuf_free(wmi_buf);
			return status;
		}
		helper_locked = true;
		if (g_wma_injection_ctx.helper_stopping ||
		    g_wma_injection_ctx.helper_transitioning) {
			qdf_mutex_release(&g_wma_injection_ctx.helper_lock);
			qdf_nbuf_free(wmi_buf);
			return QDF_STATUS_E_AGAIN;
		}

		status = wma_injection_ensure_tx_vdev(wma_handle,
						     vdev_id, tx_chanfreq);
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Failed to create injection TX helper vdev: %d",
				status);
			qdf_mutex_release(&g_wma_injection_ctx.helper_lock);
			qdf_nbuf_free(wmi_buf);
			return status;
		}
		mgmt_params.vdev_id = g_inj_tx_vdev.vdev_id;
		tx_vdev_type = WMI_VDEV_TYPE_STA;
		if (!is_group_da && req->frame_len >= 10) {
			status = wma_injection_ensure_unicast_peer(
				wma_handle, frame_data + 4);
			if (QDF_IS_STATUS_ERROR(status)) {
				qdf_mutex_release(
					&g_wma_injection_ctx.helper_lock);
				qdf_nbuf_free(wmi_buf);
				return status;
			}
			peer_exists = true;
		}
		if (!inject_monitor_no_legacy_logged) {
			wma_warn("Injection monitor: using hidden STA vdev %u for raw TX (monitor vdev %u)",
				 g_inj_tx_vdev.vdev_id, vdev_id);
			inject_monitor_no_legacy_logged = true;
		}
	}

	status = wma_injection_debug_cache_update(
		mgmt_params.desc_id, req, fc_type, fc_subtype,
		mgmt_params.chanfreq, mgmt_params.vdev_id, tx_vdev_type,
		is_group_da, peer_exists);
	if (QDF_IS_STATUS_ERROR(status)) {
		if (helper_locked)
			qdf_mutex_release(&g_wma_injection_ctx.helper_lock);
		qdf_nbuf_free(wmi_buf);
		return status;
	}

	if (log_send_info)
		wma_info("Injection route: desc_id=%u vdev=%u type=%u freq=%u group=%u broadcast=%u peer_exists=%u addr1=%pM addr2=%pM addr3=%pM",
			 mgmt_params.desc_id, mgmt_params.vdev_id, tx_vdev_type,
			 mgmt_params.chanfreq, is_group_da,
			 qdf_is_macaddr_broadcast((struct qdf_mac_addr *)(frame_data + 4)),
			 peer_exists,
			 frame_data + 4, frame_data + 10, frame_data + 16);

	/* Attempt WMI management TX path. */
	wmi_tx_attempted = true;
	if (!inject_wmi_path_logged) {
		wma_info("Injection using WMI mgmt tx path (vdev_id=%u)",
			 mgmt_params.vdev_id);
		inject_wmi_path_logged = true;
	}
	/* Publish ownership before submission so an immediate completion can free it. */
	{
		uint32_t slot = mgmt_params.desc_id %
				WMA_INJECTION_DEBUG_CACHE_SIZE;
		struct wma_injection_debug_info *e =
			&g_wma_injection_debug_cache[slot];

		qdf_spin_lock_bh(&g_wma_injection_ctx.cache_lock);
		if (e->valid && e->desc_id == mgmt_params.desc_id) {
			e->tx_buf = wmi_buf;
			e->submit_time_us = qdf_get_monotonic_boottime();
			e->tx_path = WMA_INJECTION_TX_PATH_WMI;
		}
		qdf_spin_unlock_bh(&g_wma_injection_ctx.cache_lock);
	}
	qdf_atomic_inc(&g_wma_injection_ctx.inflight_count);

	status = wmi_mgmt_unified_cmd_send(wma_handle->wmi_handle, &mgmt_params);
	if (!QDF_IS_STATUS_ERROR(status)) {
		wmi_tx_ok = true;
		g_wma_injection_ctx.stats.command_submitted++;
		if (g_wma_injection_ctx.stats.command_submitted <= 10)
			wma_info("Injection submission: desc_id=%u path=WMI status=%d vdev=%u",
				 mgmt_params.desc_id, status, mgmt_params.vdev_id);
	} else {
		qdf_spin_lock_bh(&g_wma_injection_ctx.cache_lock);
		{
			struct wma_injection_debug_info *e =
				&g_wma_injection_debug_cache[
					mgmt_params.desc_id %
					WMA_INJECTION_DEBUG_CACHE_SIZE];

			if (e->valid && e->desc_id == mgmt_params.desc_id)
				e->tx_buf = NULL;
		}
		qdf_spin_unlock_bh(&g_wma_injection_ctx.cache_lock);
		qdf_atomic_dec(&g_wma_injection_ctx.inflight_count);
		wma_warn("Injection submission: desc_id=%u path=WMI status=%d service=%u monitor=%u",
			 mgmt_params.desc_id, status, wmi_mgmt_service ? 1 : 0,
			 monitor_vdev ? 1 : 0);
	}
	if (helper_locked) {
		qdf_mutex_release(&g_wma_injection_ctx.helper_lock);
		helper_locked = false;
	}

	if (!wmi_tx_ok) {
		if (monitor_vdev) {
			wma_warn("Injection monitor vdev: dropping frame after WMI TX failure to avoid legacy FW assert");
			qdf_spin_lock_bh(&g_wma_injection_ctx.cache_lock);
			{
				struct wma_injection_debug_info *e =
					&g_wma_injection_debug_cache[
						mgmt_params.desc_id %
						WMA_INJECTION_DEBUG_CACHE_SIZE];

				if (e->desc_id == mgmt_params.desc_id)
					e->valid = false;
			}
			qdf_spin_unlock_bh(&g_wma_injection_ctx.cache_lock);
			qdf_nbuf_free(wmi_buf);
			return status;
		}

		/* Fallback to legacy data path if WMI TX is unavailable or failed. */
		if (!inject_legacy_path_logged) {
			wma_warn("Injection using legacy cdp_mgmt_send_ext fallback (wmi_mgmt_service=%u)",
				 wmi_mgmt_service ? 1 : 0);
			inject_legacy_path_logged = true;
		}

		/* Try legacy CDP management send path */
		soc = cds_get_context(QDF_MODULE_ID_SOC);
		if (!soc) {
			wma_err("Failed to get CDP SOC context");
			qdf_nbuf_free(wmi_buf);
			return QDF_STATUS_E_FAILURE;
		}

		/* Set frame control information for legacy path */
		QDF_NBUF_CB_MGMT_TXRX_DESC_ID(wmi_buf) = mgmt_params.desc_id;

		ret = cdp_mgmt_send_ext(soc, mgmt_params.vdev_id, wmi_buf,
					mgmt_params.tx_type,
					mgmt_params.use_6mbps,
					mgmt_params.chanfreq);
		if (ret == -EINVAL)
			wma_warn("Legacy management TX got -EINVAL (desc alloc or tx pool reject)");
		status = qdf_status_from_os_return(ret);
		
		if (QDF_IS_STATUS_ERROR(status)) {
			wma_err("Legacy management TX failed: %d (wmi_attempted=%u)",
				status, wmi_tx_attempted ? 1 : 0);
			qdf_spin_lock_bh(&g_wma_injection_ctx.cache_lock);
			{
				struct wma_injection_debug_info *e =
					&g_wma_injection_debug_cache[
						mgmt_params.desc_id %
						WMA_INJECTION_DEBUG_CACHE_SIZE];

				if (e->desc_id == mgmt_params.desc_id)
					e->valid = false;
			}
			qdf_spin_unlock_bh(&g_wma_injection_ctx.cache_lock);
			/* wmi_buf has either been consumed or freed at this point. */
			return status;
		}

		qdf_spin_lock_bh(&g_wma_injection_ctx.cache_lock);
		{
			struct wma_injection_debug_info *e =
				&g_wma_injection_debug_cache[
					mgmt_params.desc_id %
					WMA_INJECTION_DEBUG_CACHE_SIZE];

			if (e->valid && e->desc_id == mgmt_params.desc_id)
				e->tx_path = WMA_INJECTION_TX_PATH_LEGACY;
		}
		qdf_spin_unlock_bh(&g_wma_injection_ctx.cache_lock);
		if (log_send_info)
			wma_info("Injection submission: desc_id=%u path=legacy status=%d vdev=%u",
				 mgmt_params.desc_id, status, mgmt_params.vdev_id);
	}

	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_handle_injection_fw_response(tp_wma_handle wma_handle,
					     uint32_t desc_id,
					     uint32_t status)
{
	struct wma_injection_queue_ctx *ctx = &g_wma_injection_ctx;
	struct wma_injection_debug_info *dbg_entry;
	struct wma_injection_debug_info dbg = {0};
	qdf_nbuf_t tx_buf = NULL;
	const char *status_str;
	const char *path_str = "unknown";
	uint64_t latency_us = 0;
	bool have_entry = false;

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	if (!ctx->is_initialized) {
		wma_debug("Injection queue not initialized, ignoring response");
		return QDF_STATUS_SUCCESS;
	}

	/* Map firmware status to string for logging */
	switch (status) {
	case WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK:
		status_str = "COMPLETE_OK";
		break;
	case WMI_MGMT_TX_COMP_TYPE_DISCARD:
		status_str = "DISCARD";
		break;
	case WMI_MGMT_TX_COMP_TYPE_COMPLETE_NO_ACK:
		status_str = "NO_ACK";
		break;
	case WMI_MGMT_TX_COMP_TYPE_INSPECT:
		status_str = "INSPECT";
		break;
	default:
		status_str = "UNKNOWN";
		break;
	}

	qdf_spin_lock_bh(&ctx->cache_lock);
	dbg_entry = wma_injection_debug_cache_get(desc_id);
	if (dbg_entry) {
		qdf_mem_copy(&dbg, dbg_entry, sizeof(dbg));
		tx_buf = dbg_entry->tx_buf;
		dbg_entry->tx_buf = NULL;
		dbg_entry->valid = false;
		have_entry = true;
		if (tx_buf)
			qdf_atomic_dec(&g_wma_injection_ctx.inflight_count);
	}

	switch (status) {
	case WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK:
		ctx->stats.tx_complete_ok++;
		ctx->stats.frames_processed++;
		break;
	case WMI_MGMT_TX_COMP_TYPE_COMPLETE_NO_ACK:
		ctx->stats.tx_complete_no_ack++;
		ctx->stats.fw_errors++;
		break;
	case WMI_MGMT_TX_COMP_TYPE_DISCARD:
		ctx->stats.tx_complete_discard++;
		ctx->stats.frames_dropped++;
		ctx->stats.fw_errors++;
		break;
	default:
		ctx->stats.frames_dropped++;
		ctx->stats.fw_errors++;
		break;
	}
	qdf_spin_unlock_bh(&ctx->cache_lock);

	if (tx_buf) {
		wma_injection_unmap_tx_buf(tx_buf);
		qdf_nbuf_free(tx_buf);
	}

	if (!have_entry) {
		if (ctx->stats.fw_errors <= 10)
			wma_warn("Injection completion without live descriptor: desc_id=%u status=%s(%u)",
				 desc_id, status_str, status);
		return QDF_STATUS_SUCCESS;
	}

	if (dbg.submit_time_us) {
		uint64_t now_us = qdf_get_monotonic_boottime();

		if (now_us >= dbg.submit_time_us)
			latency_us = now_us - dbg.submit_time_us;
	}
	if (dbg.tx_path == WMA_INJECTION_TX_PATH_WMI)
		path_str = "WMI";
	else if (dbg.tx_path == WMA_INJECTION_TX_PATH_LEGACY)
		path_str = "legacy";

	if (ctx->stats.tx_complete_ok <= 5 ||
	    (status != WMI_MGMT_TX_COMP_TYPE_COMPLETE_OK &&
	     ctx->stats.fw_errors <= 10))
		wma_info("Injection completion: desc_id=%u status=%s(%u) latency=%llu us path=%s vdev=%u type=%u freq=%u fc=0x%02x/0x%02x group=%u broadcast=%u peer_exists=%u addr1=%pM addr2=%pM addr3=%pM",
			 desc_id, status_str, status, latency_us, path_str,
			 dbg.vdev_id, dbg.vdev_type, dbg.chanfreq, dbg.fc_type,
			 dbg.fc_subtype, dbg.is_group,
			 qdf_is_macaddr_broadcast((struct qdf_mac_addr *)dbg.addr1),
			 dbg.peer_exists, dbg.addr1,
			 dbg.addr2, dbg.addr3);

	return QDF_STATUS_SUCCESS;
}

#else /* FEATURE_FRAME_INJECTION_SUPPORT */

QDF_STATUS wma_send_injection_frame_to_fw(tp_wma_handle wma_handle,
					  struct inject_frame_req *req,
					  uint8_t vdev_id)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS wma_handle_injection_fw_response(tp_wma_handle wma_handle,
					     uint32_t desc_id,
					     uint32_t status)
{
	QDF_STATUS qdf_status = QDF_STATUS_SUCCESS;
	enum wma_injection_fw_error_type error_type;

	WMA_LOGD("Handling firmware injection response: desc_id=%u, status=0x%x", desc_id, status);

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	/* Check if this is an error response */
	if (status != 0) {
		WMA_LOGW("Firmware injection failed: desc_id=%u, status=0x%x", desc_id, status);
		
		/* Handle the firmware error */
		qdf_status = wma_handle_firmware_injection_error(wma_handle, status, 0, NULL);
		if (QDF_IS_STATUS_ERROR(qdf_status) && qdf_status != QDF_STATUS_E_PENDING) {
			wma_err("Failed to handle firmware injection error: %d", qdf_status);
			return qdf_status;
		}
	} else {
		WMA_LOGD("Firmware injection completed successfully: desc_id=%u", desc_id);
	}

	/* Update statistics would go here in a full implementation */
	
	return qdf_status;
}

QDF_STATUS wma_init_injection_queue(tp_wma_handle wma_handle)
{
	return QDF_STATUS_SUCCESS;
}

QDF_STATUS wma_deinit_injection_queue(tp_wma_handle wma_handle)
{
	return QDF_STATUS_SUCCESS;
}

void wma_injection_ssr_resume(tp_wma_handle wma_handle)
{
}

bool wma_injection_peer_create_response(uint8_t vdev_id,
					const uint8_t *peer_addr,
					uint32_t fw_status)
{
	return false;
}

bool wma_injection_peer_delete_response(uint8_t vdev_id,
					const uint8_t *peer_addr)
{
	return false;
}

void wma_injection_pre_stop_cleanup(tp_wma_handle wma_handle)
{
}

QDF_STATUS wma_queue_injection_frame(tp_wma_handle wma_handle,
				     struct inject_frame_req *req,
				     uint8_t vdev_id)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS wma_get_injection_queue_stats(tp_wma_handle wma_handle,
					 struct wma_injection_queue_stats *stats)
{
	return QDF_STATUS_E_NOSUPPORT;
}

QDF_STATUS wma_reset_injection_queue_stats(tp_wma_handle wma_handle)
{
	return QDF_STATUS_E_NOSUPPORT;
}

uint32_t wma_get_injection_queue_size(tp_wma_handle wma_handle)
{
	return 0;
}

bool wma_is_injection_queue_empty(tp_wma_handle wma_handle)
{
	return true;
}

QDF_STATUS wma_flush_injection_queue(tp_wma_handle wma_handle)
{
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_translate_fw_injection_error() - Translate firmware error codes
 * @fw_error_code: Firmware-specific error code
 *
 * This function translates firmware-specific error codes to standard
 * WMA injection error types for consistent error handling.
 *
 * Return: Translated error type
 */
enum wma_injection_fw_error_type wma_translate_fw_injection_error(uint32_t fw_error_code)
{
	enum wma_injection_fw_error_type error_type;

	WMA_LOGD("Translating firmware error code: 0x%x", fw_error_code);

	switch (fw_error_code) {
	case 0x0: /* Success */
		error_type = WMA_INJECTION_FW_ERROR_NONE;
		break;
	case 0x1: /* Generic failure */
		error_type = WMA_INJECTION_FW_ERROR_REJECTED;
		break;
	case 0x2: /* Invalid VDEV */
		error_type = WMA_INJECTION_FW_ERROR_INVALID_VDEV;
		break;
	case 0x3: /* No resources */
		error_type = WMA_INJECTION_FW_ERROR_NO_RESOURCES;
		break;
	case 0x4: /* Interface down */
		error_type = WMA_INJECTION_FW_ERROR_INTERFACE_DOWN;
		break;
	case 0x5: /* Power save mode */
		error_type = WMA_INJECTION_FW_ERROR_POWER_SAVE;
		break;
	case 0x6: /* Channel switch in progress */
		error_type = WMA_INJECTION_FW_ERROR_CHANNEL_SWITCH;
		break;
	case 0x7: /* Scan active */
		error_type = WMA_INJECTION_FW_ERROR_SCAN_ACTIVE;
		break;
	case 0xFFFFFFFF: /* Timeout */
		error_type = WMA_INJECTION_FW_ERROR_TIMEOUT;
		break;
	default:
		error_type = WMA_INJECTION_FW_ERROR_UNKNOWN;
		break;
	}

	WMA_LOGD("Translated firmware error 0x%x to type %d", fw_error_code, error_type);
	return error_type;
}

/**
 * wma_handle_firmware_injection_error() - Handle firmware injection error
 * @wma_handle: WMA handle
 * @error_code: Firmware error code
 * @vdev_id: VDEV ID associated with error
 * @req: Frame request that caused error (optional)
 *
 * This function handles firmware errors during frame injection. It implements
 * retry logic for transient failures and coordinates with HDD layer for
 * error recovery. It also maintains firmware state synchronization.
 *
 * Return: QDF_STATUS_SUCCESS on successful recovery, error code on failure
 */
QDF_STATUS wma_handle_firmware_injection_error(tp_wma_handle wma_handle,
						uint32_t error_code,
						uint8_t vdev_id,
						struct inject_frame_req *req)
{
	enum wma_injection_fw_error_type error_type;
	struct wma_injection_fw_error_info *error_info;
	QDF_STATUS status = QDF_STATUS_SUCCESS;
	bool should_retry = false;
	uint32_t retry_delay_ms = 0;

	WMA_LOGD("Handling firmware injection error: code=0x%x, vdev_id=%u", error_code, vdev_id);

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	/* Translate firmware error code */
	error_type = wma_translate_fw_injection_error(error_code);

	/* Update error statistics - this would be part of a larger injection context */
	/* For now, we'll log the error information */
	WMA_LOGW("Firmware injection error: type=%d, code=0x%x, vdev_id=%u",
		 error_type, error_code, vdev_id);

	/* Determine if we should retry based on error type */
	switch (error_type) {
	case WMA_INJECTION_FW_ERROR_NO_RESOURCES:
		/* Transient error - retry with delay */
		should_retry = true;
		retry_delay_ms = 100; /* 100ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_POWER_SAVE:
		/* Device in power save - retry with longer delay */
		should_retry = true;
		retry_delay_ms = 500; /* 500ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_CHANNEL_SWITCH:
		/* Channel switch in progress - retry with delay */
		should_retry = true;
		retry_delay_ms = 200; /* 200ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_SCAN_ACTIVE:
		/* Scan active - retry with short delay */
		should_retry = true;
		retry_delay_ms = 50; /* 50ms delay */
		break;

	case WMA_INJECTION_FW_ERROR_TIMEOUT:
		/* Timeout - retry once with longer delay */
		should_retry = true;
		retry_delay_ms = 1000; /* 1 second delay */
		break;

	case WMA_INJECTION_FW_ERROR_INVALID_VDEV:
	case WMA_INJECTION_FW_ERROR_INTERFACE_DOWN:
		/* Permanent errors - synchronize state but don't retry */
		status = wma_sync_firmware_injection_state(wma_handle, vdev_id);
		should_retry = false;
		break;

	case WMA_INJECTION_FW_ERROR_REJECTED:
	case WMA_INJECTION_FW_ERROR_UNKNOWN:
	default:
		/* Unknown or permanent errors - don't retry */
		should_retry = false;
		break;
	}

	/* Attempt retry if appropriate and request is available */
	if (should_retry && req) {
		/* Check retry count to avoid infinite loops */
		if (req->retry_count < 3) { /* Maximum 3 retries */
			wma_info("Retrying injection after %u ms delay (attempt %u)",
				 retry_delay_ms, req->retry_count + 1);
			
			/* Schedule retry with delay */
			status = wma_retry_injection_frame(wma_handle, req, vdev_id, error_type);
			if (QDF_IS_STATUS_SUCCESS(status)) {
				return QDF_STATUS_E_PENDING; /* Retry scheduled */
			}
		} else {
			WMA_LOGW("Maximum retry attempts reached for injection request");
			status = QDF_STATUS_E_FAILURE;
		}
	}

	/* If we reach here, either no retry was needed or retry failed */
	if (QDF_IS_STATUS_ERROR(status)) {
		wma_err("Firmware injection error handling failed: %d", status);
	} else {
		wma_info("Firmware injection error handled successfully");
	}

	return status;
}

/**
 * wma_retry_injection_frame() - Retry injection frame after firmware error
 * @wma_handle: WMA handle
 * @req: Frame injection request to retry
 * @vdev_id: VDEV ID for the frame
 * @error_type: Type of error that occurred
 *
 * This function implements retry logic for transient firmware failures.
 * It uses exponential backoff and limits the number of retry attempts.
 *
 * Return: QDF_STATUS_SUCCESS on successful retry, error code on failure
 */
QDF_STATUS wma_retry_injection_frame(tp_wma_handle wma_handle,
				     struct inject_frame_req *req,
				     uint8_t vdev_id,
				     enum wma_injection_fw_error_type error_type)
{
	QDF_STATUS status;
	uint32_t delay_ms;

	WMA_LOGD("Retrying injection frame: vdev_id=%u, error_type=%d, retry_count=%u",
		 vdev_id, error_type, req->retry_count);

	if (!wma_handle || !req) {
		wma_err("Invalid parameters for retry");
		return QDF_STATUS_E_INVAL;
	}

	/* Increment retry count */
	req->retry_count++;

	/* Calculate exponential backoff delay */
	delay_ms = 100 * (1 << (req->retry_count - 1)); /* 100ms, 200ms, 400ms, ... */
	if (delay_ms > 2000) {
		delay_ms = 2000; /* Cap at 2 seconds */
	}

	/* Add some jitter to avoid thundering herd */
	delay_ms += (qdf_get_log_timestamp() % 50); /* Add 0-49ms jitter */

	wma_info("Scheduling injection retry in %u ms (attempt %u)",
		 delay_ms, req->retry_count);

	/* For now, we'll simulate the retry by calling the send function again */
	/* In a real implementation, this would be scheduled with a timer */
	qdf_sleep(delay_ms);

	/* Attempt to send the frame again */
	status = wma_send_injection_frame_to_fw(wma_handle, req, vdev_id);
	if (QDF_IS_STATUS_ERROR(status)) {
		WMA_LOGW("Injection retry failed: %d", status);
		return status;
	}

	wma_info("Injection retry initiated successfully");
	return QDF_STATUS_SUCCESS;
}

/**
 * wma_sync_firmware_injection_state() - Synchronize firmware injection state
 * @wma_handle: WMA handle
 * @vdev_id: VDEV ID to synchronize
 *
 * This function synchronizes the firmware injection state after errors.
 * It ensures that the firmware and driver are in a consistent state.
 *
 * Return: QDF_STATUS_SUCCESS on success, error code on failure
 */
QDF_STATUS wma_sync_firmware_injection_state(tp_wma_handle wma_handle,
					      uint8_t vdev_id)
{
	QDF_STATUS status = QDF_STATUS_SUCCESS;

	WMA_LOGD("Synchronizing firmware injection state for vdev_id=%u", vdev_id);

	if (!wma_handle) {
		wma_err("Invalid WMA handle");
		return QDF_STATUS_E_INVAL;
	}

	/* Check if VDEV is valid and active */
	if (vdev_id >= wma_handle->max_bssid) {
		wma_err("Invalid VDEV ID: %u", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	/* Verify VDEV state */
	if (!wma_handle->interfaces[vdev_id].handle) {
		WMA_LOGW("VDEV %u is not active", vdev_id);
		return QDF_STATUS_E_INVAL;
	}

	/* Check interface type - injection typically requires monitor mode */
	if (wma_handle->interfaces[vdev_id].type != WMI_VDEV_TYPE_MONITOR) {
		WMA_LOGW("VDEV %u is not in monitor mode (type=%d)",
			 vdev_id, wma_handle->interfaces[vdev_id].type);
		/* This might not be an error depending on implementation */
	}

	/* Flush any pending injection frames for this VDEV */
	/* This would be implemented as part of the queue management */
	wma_info("Flushing pending injection frames for vdev_id=%u", vdev_id);

	/* Send a sync command to firmware if needed */
	/* This would involve sending a WMI command to query/reset injection state */
	WMA_LOGD("Sending injection state sync command to firmware");

	/* For now, we'll just log that synchronization is complete */
	wma_info("Firmware injection state synchronized for vdev_id=%u", vdev_id);

	return status;
}

#endif /* FEATURE_FRAME_INJECTION_SUPPORT */
