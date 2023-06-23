/*
 *
 * Copyright 2021-2023 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#pragma once

#include "adapters/gtpu_adapters.h"
#include "adapters/sdap_adapters.h"
#include "drb_context.h"
#include "srsran/gtpu/gtpu_demux.h"
#include "srsran/gtpu/gtpu_tunnel_ngu.h"
#include "srsran/ran/up_transport_layer_info.h"

namespace srsran {
namespace srs_cu_up {

#define MAX_NUM_PDU_SESSIONS_PER_UE (8) /// Todo: find 3GPP spec reference

/// \brief Context for PDU session with session-wide parameters and all contained DRBs.
struct pdu_session {
  pdu_session(const e1ap_pdu_session_res_to_setup_item& session, gtpu_demux_ctrl& gtpu_rx_demux_) :
    pdu_session_id(session.pdu_session_id),
    session_type(session.pdu_session_type),
    snssai(session.snssai),
    security_ind(session.security_ind),
    ul_tunnel_info(session.ng_ul_up_tnl_info),
    gtpu_rx_demux(gtpu_rx_demux_)
  {
    if (session.pdu_session_res_dl_ambr.has_value()) {
      pdu_session_res_ambr = session.pdu_session_res_dl_ambr.value();
    }
  };
  ~pdu_session()
  {
    // Remove GTP-U tunnel from GTP-U demux.
    gtpu_rx_demux.remove_tunnel(local_teid);
  }

  std::unique_ptr<sdap_entity>     sdap;
  std::unique_ptr<gtpu_tunnel_ngu> gtpu;

  // Adapters between SDAP and GTPU
  gtpu_sdap_adapter gtpu_to_sdap_adapter;
  sdap_gtpu_adapter sdap_to_gtpu_adapter;

  pdcp_f1u_adapter    pdcp_to_f1u_adapter;
  pdu_session_id_t    pdu_session_id; //< PDU session ID (0-255)
  std::string         session_type;
  s_nssai_t           snssai;
  security_indication security_ind;
  uint64_t            pdu_session_res_ambr = 0;

  // Tunneling info used by all DRBs/QoS flows in this PDU session
  up_transport_layer_info ul_tunnel_info; // the peer GTP-U address and TEID
  uint32_t                local_teid;     // the local teid used by the gNB for this PDU session
  gtpu_demux_ctrl&        gtpu_rx_demux;  // The demux entity to register/remove the tunnel.

  drb_context* default_drb = nullptr; // non-owning pointer to default DRB, if any

  std::map<drb_id_t, std::unique_ptr<drb_context>> drbs; // key is drb_id
};

} // namespace srs_cu_up
} // namespace srsran
