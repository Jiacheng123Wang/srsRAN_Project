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

#include "ofh_data_flow_uplane_downlink_data.h"
#include "sequence_identifier_generator.h"
#include "srsran/ofh/compression/iq_compressor.h"
#include "srsran/ofh/ecpri/ecpri_packet_builder.h"
#include "srsran/ofh/ethernet/vlan_ethernet_frame_builder.h"
#include "srsran/ofh/serdes/ofh_uplane_message_builder.h"
#include "srsran/ran/cyclic_prefix.h"

namespace srsran {
struct resource_grid_context;

namespace ether {
class eth_frame_pool;
}

namespace ofh {

/// Open Fronthaul User-Plane downlink data flow implementation configuration.
struct data_flow_uplane_downlink_data_impl_config {
  /// Cyclic prefix.
  cyclic_prefix cp;
  /// RU bandwidth in PRBs.
  unsigned ru_nof_prbs;
  /// VLAN frame parameters.
  ether::vlan_frame_params vlan_params;
  /// Compression parameters.
  ru_compression_params compr_params;
};

/// Open Fronthaul User-Plane downlink data flow implementation dependencies.
struct data_flow_uplane_downlink_data_impl_dependencies {
  /// Logger
  srslog::basic_logger* logger = nullptr;
  /// Ethernet frame pool.
  std::shared_ptr<ether::eth_frame_pool> frame_pool;
  /// VLAN frame builder.
  std::unique_ptr<ether::vlan_frame_builder> eth_builder;
  /// eCPRI packet builder.
  std::unique_ptr<ecpri::packet_builder> ecpri_builder;
  /// IQ compressor.
  std::unique_ptr<iq_compressor> compressor_sel;
  /// User-Plane message builder.
  std::unique_ptr<uplane_message_builder> up_builder;
};

/// Open Fronthaul User-Plane downlink data flow implementation.
class data_flow_uplane_downlink_data_impl : public data_flow_uplane_downlink_data
{
public:
  explicit data_flow_uplane_downlink_data_impl(const data_flow_uplane_downlink_data_impl_config&  config,
                                               data_flow_uplane_downlink_data_impl_dependencies&& dependencies);

  /// Enqueues the User-Plane downlink data messages with the given context and resource grid.
  void enqueue_section_type_1_message(const data_flow_uplane_resource_grid_context& context,
                                      const resource_grid_reader&                   grid) override;

private:
  /// Enqueues an User-Plane message burst.
  void enqueue_section_type_1_message_symbol_burst(const data_flow_uplane_resource_grid_context& context,
                                                   const resource_grid_reader&                   grid);

  /// Enqueues an User-Plane message symbol with the given context and grid.
  unsigned enqueue_section_type_1_message_symbol(span<const cf_t>             iq_symbol_data,
                                                 const uplane_message_params& params,
                                                 unsigned                     eaxc,
                                                 span<uint8_t>                buffer);

  /// Reads the contents of the resource grid.
  span<const cf_t> read_grid(unsigned symbol, unsigned port, const resource_grid_reader& grid) const;

private:
  srslog::basic_logger&                      logger;
  const unsigned                             nof_symbols_per_slot;
  const unsigned                             ru_nof_prbs;
  const ether::vlan_frame_params             vlan_params;
  const ru_compression_params                compr_params;
  sequence_identifier_generator              up_seq_gen;
  std::shared_ptr<ether::eth_frame_pool>     frame_pool_ptr;
  ether::eth_frame_pool&                     frame_pool;
  std::unique_ptr<iq_compressor>             compressor_sel;
  std::unique_ptr<ether::vlan_frame_builder> eth_builder;
  std::unique_ptr<ecpri::packet_builder>     ecpri_builder;
  std::unique_ptr<uplane_message_builder>    up_builder;
};

} // namespace ofh
} // namespace srsran
