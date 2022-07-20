/*
 *
 * Copyright 2013-2022 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#pragma once

#include "srsgnb/adt/byte_buffer.h"
#include "srsgnb/adt/byte_buffer_slice_chain.h"
#include "srsgnb/pdcp/pdcp_rx.h"
#include "srsgnb/ran/bearer_logger.h"

namespace srsgnb {
/// Base class used for receiving RLC bearers.
/// It provides interfaces for the RLC bearers, for the lower layers
class pdcp_entity_rx : public pdcp_rx_lower_interface
{
public:
  pdcp_entity_rx(pdcp_rx_upper_data_notifier& upper_dn) : upper_dn(upper_dn) {}

private:
  pdcp_rx_upper_data_notifier& upper_dn;

  void handle_pdu(byte_buffer buf) final { upper_dn.on_new_sdu(std::move(buf)); }
};
} // namespace srsgnb
