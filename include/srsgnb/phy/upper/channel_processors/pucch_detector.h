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

#include "srsgnb/phy/upper/channel_estimation.h"
#include "srsgnb/phy/upper/channel_processors/pucch_uci_message.h"

namespace srsgnb {

/// PUCCH detector interface for Formats 0 and 1.
class pucch_detector
{
public:
  /// Collects PUCCH format 0 detector parameters.
  struct format0_configuration {
    // Add here PUCCH demodulator parameters...
  };

  /// Collects PUCCH format 1 detector parameters.
  struct format1_configuration {
    // Add here PUCCH demodulator parameters...
  };

  /// Default destructor.
  virtual ~pucch_detector() = default;

  /// \brief Demodulates a PUCCH format 0 transmission.
  /// \param[in]  grid   Input resource grid.
  /// \param[in]  config PUCCH format 0 configuration parameters.
  /// \return A pair containing the detected PUCCH message and the channel state information.
  virtual std::pair<pucch_uci_message, channel_state_information>
  detect_format0(const resource_grid_reader& grid, const format0_configuration& config) = 0;

  /// \brief Demodulates a PUCCH format 1 transmission.
  /// \param[in]  grid      Input resource grid.
  /// \param[in]  estimates Estimated channel.
  /// \param[in]  config    PUCCH format 1 configuration parameters.
  /// \return The detected PUCCH message.
  virtual pucch_uci_message detect_format1(const resource_grid_reader&  grid,
                                           const channel_estimate&      estimates,
                                           const format1_configuration& config) = 0;
};
} // namespace srsgnb