/*
 *
 * Copyright 2021-2024 Software Radio Systems Limited
 *
 * This file is part of srsRAN.
 *
 * srsRAN is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * srsRAN is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * A copy of the GNU Affero General Public License can be found in
 * the LICENSE file in the top-level directory of this distribution
 * and at http://www.gnu.org/licenses/.
 *
 */

#pragma once

#include "srsran/phy/support/precoding_formatters.h"
#include "srsran/phy/support/re_pattern_formatters.h"
#include "srsran/phy/upper/channel_processors/pdcch_processor.h"
#include "srsran/phy/upper/channel_processors/prach_detector.h"
#include "srsran/phy/upper/channel_processors/ssb_processor.h"
#include "srsran/phy/upper/channel_state_information_formatters.h"
#include "srsran/ran/pdcch/pdcch_context_formatter.h"
#include "srsran/srsvec/copy.h"

namespace fmt {

/// \brief Custom formatter for \c pdcch_processor::coreset_description.
template <>
struct formatter<srsran::pdcch_processor::coreset_description> {
  /// Helper used to parse formatting options and format fields.
  srsran::delimited_formatter helper;

  /// Default constructor.
  formatter() = default;

  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return helper.parse(ctx);
  }

  template <typename FormatContext>
  auto format(const srsran::pdcch_processor::coreset_description& coreset, FormatContext& ctx)
  {
    helper.format_always(ctx, "bwp=[{}, {})", coreset.bwp_start_rb, coreset.bwp_start_rb + coreset.bwp_size_rb);
    helper.format_always(
        ctx, "symb=[{}, {})", coreset.start_symbol_index, coreset.start_symbol_index + coreset.duration);
    helper.format_always(ctx, "f_re={}", coreset.frequency_resources);

    switch (coreset.cce_to_reg_mapping) {
      case srsran::pdcch_processor::cce_to_reg_mapping_type::CORESET0:
        helper.format_if_verbose(ctx, "mapping=coreset0");
        break;
      case srsran::pdcch_processor::cce_to_reg_mapping_type::INTERLEAVED:
        helper.format_if_verbose(ctx, "mapping=interleaved");
        helper.format_if_verbose(ctx, "reg_bundle_size={}", coreset.reg_bundle_size);
        helper.format_if_verbose(ctx, "interleaver_size={}", coreset.interleaver_size);
        break;
      case srsran::pdcch_processor::cce_to_reg_mapping_type::NON_INTERLEAVED:
        helper.format_if_verbose(ctx, "mapping=non-interleaved");
        break;
    }

    helper.format_if_verbose(ctx, "shift_idx={}", coreset.shift_index);

    return ctx.out();
  }
};

/// \brief Custom formatter for \c pdcch_processor::pdu_t.
template <>
struct formatter<srsran::pdcch_processor::pdu_t> {
  /// Helper used to parse formatting options and format fields.
  srsran::delimited_formatter helper;

  /// Default constructor.
  formatter() = default;

  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return helper.parse(ctx);
  }

  template <typename FormatContext>
  auto format(const srsran::pdcch_processor::pdu_t& pdu, FormatContext& ctx)
  {
    helper.format_always(ctx, "rnti=0x{:04x}", pdu.dci.rnti);
    if (pdu.context.has_value()) {
      helper.format_always(ctx, pdu.context.value());
    }
    helper.format_if_verbose(ctx, "slot={}", pdu.slot);
    helper.format_if_verbose(ctx, "cp={}", pdu.cp.to_string());
    helper.format_if_verbose(ctx, pdu.coreset);
    helper.format_always(ctx, "cce={}", pdu.dci.cce_index);
    helper.format_always(ctx, "al={}", pdu.dci.aggregation_level);
    helper.format_if_verbose(ctx, "size={}", pdu.dci.payload.size());
    helper.format_if_verbose(ctx, "n_id_dmrs={}", pdu.dci.n_id_pdcch_dmrs);
    helper.format_if_verbose(ctx, "n_id_data={}", pdu.dci.n_id_pdcch_data);
    helper.format_if_verbose(ctx, "n_rnti={}", pdu.dci.n_rnti);
    helper.format_if_verbose(ctx, "power_dmrs={:+.1f}dB", pdu.dci.dmrs_power_offset_dB);
    helper.format_if_verbose(ctx, "power_data={:+.1f}dB", pdu.dci.data_power_offset_dB);
    helper.format_if_verbose(ctx, "precoding={}", pdu.dci.precoding);
    return ctx.out();
  }
};

/// \brief Custom formatter for \c prach_detector::configuration.
template <>
struct formatter<srsran::prach_detector::configuration> {
  /// Helper used to parse formatting options and format fields.
  srsran::delimited_formatter helper;

  /// Default constructor.
  formatter() = default;

  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return helper.parse(ctx);
  }

  template <typename FormatContext>
  auto format(const srsran::prach_detector::configuration& config, FormatContext& ctx)
  {
    helper.format_always(ctx, "rsi={}", config.root_sequence_index);
    helper.format_if_verbose(ctx,
                             "preambles=[{}, {})",
                             config.start_preamble_index,
                             config.start_preamble_index + config.nof_preamble_indices);
    helper.format_if_verbose(ctx, "format={}", to_string(config.format));
    helper.format_if_verbose(ctx, "set={}", to_string(config.restricted_set));
    helper.format_if_verbose(ctx, "zcz={}", config.zero_correlation_zone);
    helper.format_if_verbose(ctx, "scs={}", to_string(config.ra_scs));
    helper.format_if_verbose(ctx, "nof_rx_ports={}", config.nof_rx_ports);

    return ctx.out();
  }
};

/// \brief Custom formatter for \c prach_detection_result::preamble_indication.
template <>
struct formatter<srsran::prach_detection_result::preamble_indication> {
  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return ctx.begin();
  }

  template <typename FormatContext>
  auto format(const srsran::prach_detection_result::preamble_indication& preamble, FormatContext& ctx)
  {
    format_to(ctx.out(),
              "{{idx={} ta={:.2f}us detection_metric={:.1f}}}",
              preamble.preamble_index,
              preamble.time_advance.to_seconds() * 1e6,
              preamble.detection_metric);
    return ctx.out();
  }
};

/// \brief Custom formatter for \c prach_detection_result.
template <>
struct formatter<srsran::prach_detection_result> {
  /// Helper used to parse formatting options and format fields.
  srsran::delimited_formatter helper;

  /// Default constructor.
  formatter() = default;

  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return helper.parse(ctx);
  }

  template <typename FormatContext>
  auto format(const srsran::prach_detection_result& result, FormatContext& ctx)
  {
    helper.format_always(ctx, "rssi={:+.1f}dB", result.rssi_dB);
    helper.format_if_verbose(ctx, "res={:.1f}us", result.time_resolution.to_seconds() * 1e6);
    helper.format_if_verbose(ctx, "max_ta={:.2f}us", result.time_advance_max.to_seconds() * 1e6);
    helper.format_always(ctx,
                         "detected_preambles=[{:,}]",
                         srsran::span<const srsran::prach_detection_result::preamble_indication>(result.preambles));

    return ctx.out();
  }
};

/// \brief Custom formatter for \c ssb_processor::pdu_t.
template <>
struct formatter<srsran::ssb_processor::pdu_t> {
  /// Helper used to parse formatting options and format fields.
  srsran::delimited_formatter helper;

  /// Default constructor.
  formatter() = default;

  template <typename ParseContext>
  auto parse(ParseContext& ctx)
  {
    return helper.parse(ctx);
  }

  template <typename FormatContext>
  auto format(const srsran::ssb_processor::pdu_t& pdu, FormatContext& ctx)
  {
    helper.format_always(ctx, "pci={}", pdu.phys_cell_id);
    helper.format_always(ctx, "ssb_idx={}", pdu.ssb_idx);
    helper.format_always(ctx, "L_max={}", pdu.L_max);
    helper.format_always(ctx, "common_scs={}", scs_to_khz(pdu.common_scs));
    helper.format_always(ctx, "sc_offset={}", pdu.subcarrier_offset.value());
    helper.format_always(ctx, "offset_PointA={}", pdu.offset_to_pointA.value());
    helper.format_always(ctx, "pattern={}", to_string(pdu.pattern_case));

    helper.format_if_verbose(ctx, "beta_pss={:+.1f}dB", pdu.beta_pss);
    helper.format_if_verbose(ctx, "slot={}", pdu.slot);
    helper.format_if_verbose(ctx, "ports={}", srsran::span<const uint8_t>(pdu.ports));

    return ctx.out();
  }
};

} // namespace fmt
