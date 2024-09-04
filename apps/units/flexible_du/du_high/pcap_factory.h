/*
 *
 * Copyright 2021-2024 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#pragma once

#include "apps/services/worker_manager.h"
#include "srsran/pcap/dlt_pcap.h"
#include "srsran/pcap/mac_pcap.h"
#include "srsran/pcap/rlc_pcap.h"

namespace srsran {
namespace modules {
namespace flexible_du {

struct du_pcaps {
  // DLT PCAPs
  std::unique_ptr<dlt_pcap> f1ap;
  std::unique_ptr<dlt_pcap> f1u;
  std::unique_ptr<dlt_pcap> e2ap;

  // MAC and RLC PCAPs
  std::unique_ptr<mac_pcap> mac;
  std::unique_ptr<rlc_pcap> rlc;
  void                      close()
  {
    f1ap.reset();
    f1u.reset();
    e2ap.reset();
    mac.reset();
    rlc.reset();
  }
};

/// Creates the DLT PCAP of the DU.
inline du_pcaps create_pcaps(const du_high_unit_pcap_config& pcap_cfg, worker_manager& workers)
{
  du_pcaps pcaps;

  pcaps.f1ap = pcap_cfg.f1ap.enabled ? create_f1ap_pcap(pcap_cfg.f1ap.filename, workers.get_executor("pcap_exec"))
                                     : create_null_dlt_pcap();

  pcaps.f1u = pcap_cfg.f1u.enabled ? create_gtpu_pcap(pcap_cfg.f1u.filename, workers.get_executor("f1u_pcap_exec"))
                                   : create_null_dlt_pcap();

  pcaps.e2ap = pcap_cfg.e2ap.enabled ? create_e2ap_pcap(pcap_cfg.e2ap.filename, workers.get_executor("pcap_exec"))
                                     : create_null_dlt_pcap();

  if (pcap_cfg.mac.type != "dlt" && pcap_cfg.mac.type != "udp") {
    report_error("Invalid type for MAC PCAP. type={}\n", pcap_cfg.mac.type);
  }
  pcaps.mac = pcap_cfg.mac.enabled
                  ? create_mac_pcap(pcap_cfg.mac.filename,
                                    pcap_cfg.mac.type == "dlt" ? mac_pcap_type::dlt : mac_pcap_type::udp,
                                    workers.get_executor("mac_pcap_exec"))
                  : create_null_mac_pcap();

  if (pcap_cfg.rlc.rb_type != "all" && pcap_cfg.rlc.rb_type != "srb" && pcap_cfg.rlc.rb_type != "drb") {
    report_error("Invalid rb_type for RLC PCAP. rb_type={}\n", pcap_cfg.rlc.rb_type);
  }

  pcaps.rlc = pcap_cfg.rlc.enabled ? create_rlc_pcap(pcap_cfg.rlc.filename,
                                                     workers.get_executor("rlc_pcap_exec"),
                                                     pcap_cfg.rlc.rb_type != "drb",
                                                     pcap_cfg.rlc.rb_type != "srb")
                                   : create_null_rlc_pcap();
  return pcaps;
}

} // namespace flexible_du
} // namespace modules
} // namespace srsran
