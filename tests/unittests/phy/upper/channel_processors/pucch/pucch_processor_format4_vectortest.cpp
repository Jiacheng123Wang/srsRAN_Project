/*
 *
 * Copyright 2021-2024 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#include "pucch_processor_format4_test_data.h"
#include "srsran/phy/support/support_factories.h"
#include "srsran/phy/upper/channel_processors/channel_processor_formatters.h"
#include "srsran/phy/upper/channel_processors/pucch/factories.h"
#include "srsran/phy/upper/channel_processors/pucch/formatters.h"
#include "srsran/phy/upper/equalization/equalization_factories.h"
#include "srsran/ran/pucch/pucch_constants.h"
#include "fmt/ostream.h"
#include <gtest/gtest.h>

using namespace srsran;

using PucchProcessorF4Params = test_case_t;

namespace srsran {

std::ostream& operator<<(std::ostream& os, const test_case_t& test_case)
{
  fmt::print(os,
             "grid: {} RB x {} symb, PUCCH config: {}",
             test_case.context.grid_nof_prb,
             test_case.context.grid_nof_symbols,
             test_case.context.config);
  return os;
}

std::ostream& operator<<(std::ostream& os, span<const uint8_t> data)
{
  fmt::print(os, "{}", data);
  return os;
}

} // namespace srsran

class PucchProcessorF4Fixture : public ::testing::TestWithParam<PucchProcessorF4Params>
{
protected:
  // PUCCH processor factory.
  static std::shared_ptr<pucch_processor_factory> processor_factory;
  // PUCCH processor.
  std::unique_ptr<pucch_processor> processor;
  // PUCCH processor validator.
  std::unique_ptr<pucch_pdu_validator> validator;

  static void SetUpTestSuite()
  {
    if (!processor_factory) {
      // Create factories required by the PUCCH demodulator factory.
      std::shared_ptr<channel_equalizer_factory> equalizer_factory = create_channel_equalizer_generic_factory();
      ASSERT_NE(equalizer_factory, nullptr) << "Cannot create equalizer factory.";

      std::shared_ptr<channel_modulation_factory> demod_factory = create_channel_modulation_sw_factory();
      ASSERT_NE(demod_factory, nullptr) << "Cannot create channel modulation factory.";

      std::shared_ptr<pseudo_random_generator_factory> prg_factory = create_pseudo_random_generator_sw_factory();
      ASSERT_NE(prg_factory, nullptr) << "Cannot create pseudo-random generator factory.";

      std::shared_ptr<dft_processor_factory> dft_factory = create_dft_processor_factory_fftw_slow();
      if (!dft_factory) {
        dft_factory = create_dft_processor_factory_generic();
      }
      ASSERT_NE(dft_factory, nullptr) << "Cannot create DFT factory.";

      std::shared_ptr<transform_precoder_factory> precoding_factory =
          create_dft_transform_precoder_factory(dft_factory, pucch_constants::FORMAT4_MAX_NPRB + 1);
      ASSERT_NE(precoding_factory, nullptr) << "Cannot create transform precoder factory";

      // Create PUCCH demodulator factory.
      std::shared_ptr<pucch_demodulator_factory> pucch_demod_factory =
          create_pucch_demodulator_factory_sw(equalizer_factory, demod_factory, prg_factory, precoding_factory);
      ASSERT_NE(pucch_demod_factory, nullptr) << "Cannot create PUCCH demodulator factory.";

      // Create factories required by the PUCCH channel estimator factory.
      std::shared_ptr<low_papr_sequence_generator_factory> lpg_factory =
          create_low_papr_sequence_generator_sw_factory();
      ASSERT_NE(lpg_factory, nullptr) << "Cannot create low PAPR sequence generator factory.";

      std::shared_ptr<low_papr_sequence_collection_factory> lpc_factory =
          create_low_papr_sequence_collection_sw_factory(lpg_factory);
      ASSERT_NE(lpc_factory, nullptr) << "Cannot create low PAPR sequence collection factory.";

      std::shared_ptr<time_alignment_estimator_factory> ta_estimator_factory =
          create_time_alignment_estimator_dft_factory(dft_factory);
      ASSERT_NE(ta_estimator_factory, nullptr) << "Cannot create TA estimator factory.";

      // Create channel estimator factory.
      std::shared_ptr<port_channel_estimator_factory> port_chan_estimator_factory =
          create_port_channel_estimator_factory_sw(ta_estimator_factory);
      ASSERT_NE(port_chan_estimator_factory, nullptr) << "Cannot create port channel estimator factory.";

      std::shared_ptr<dmrs_pucch_estimator_factory> estimator_factory =
          create_dmrs_pucch_estimator_factory_sw(prg_factory, lpc_factory, lpg_factory, port_chan_estimator_factory);
      ASSERT_NE(estimator_factory, nullptr) << "Cannot create DM-RS PUCCH estimator factory.";

      // Create PUCCH detector factory.
      std::shared_ptr<pucch_detector_factory> detector_factory =
          create_pucch_detector_factory_sw(lpc_factory, prg_factory, equalizer_factory);
      ASSERT_NE(detector_factory, nullptr) << "Cannot create PUCCH detector factory.";

      // Create short block detector factory.
      std::shared_ptr<short_block_detector_factory> short_block_det_factory = create_short_block_detector_factory_sw();
      ASSERT_NE(short_block_det_factory, nullptr) << "Cannot create short block detector factory.";

      // Create polar decoder factory.
      std::shared_ptr<polar_factory> polar_dec_factory = create_polar_factory_sw();
      ASSERT_NE(polar_dec_factory, nullptr) << "Invalid polar decoder factory.";

      // Create CRC calculator factory.
      std::shared_ptr<crc_calculator_factory> crc_calc_factory = create_crc_calculator_factory_sw("auto");
      ASSERT_NE(crc_calc_factory, nullptr) << "Invalid CRC calculator factory.";

      // Create UCI decoder factory.
      std::shared_ptr<uci_decoder_factory> uci_dec_factory =
          create_uci_decoder_factory_generic(short_block_det_factory, polar_dec_factory, crc_calc_factory);
      ASSERT_NE(uci_dec_factory, nullptr) << "Cannot create UCI decoder factory.";

      channel_estimate::channel_estimate_dimensions channel_estimate_dimensions;
      channel_estimate_dimensions.nof_tx_layers = 1;
      channel_estimate_dimensions.nof_rx_ports  = 4;
      channel_estimate_dimensions.nof_symbols   = MAX_NSYMB_PER_SLOT;
      channel_estimate_dimensions.nof_prb       = MAX_RB;

      // Create PUCCH processor factory.
      processor_factory = create_pucch_processor_factory_sw(
          estimator_factory, detector_factory, pucch_demod_factory, uci_dec_factory, channel_estimate_dimensions);
      ASSERT_NE(processor_factory, nullptr) << "Cannot create PUCCH processor factory.";
    }
  }

  void SetUp() override
  {
    // Assert PUCCH Processor factory.
    ASSERT_NE(processor_factory, nullptr) << "Cannot create PUCCH processor factory.";

    // Create PUCCH processor.
    processor = processor_factory->create();
    ASSERT_NE(processor, nullptr) << "Cannot create PUCCH processor.";

    // Create PUCCH validator.
    validator = processor_factory->create_validator();
    ASSERT_NE(validator, nullptr) << "Cannot create PUCCH validator.";
  }
};

std::shared_ptr<pucch_processor_factory> PucchProcessorF4Fixture::processor_factory = nullptr;

TEST_P(PucchProcessorF4Fixture, PucchProcessorF4VectorTest)
{
  const test_case_t&                            test_case = GetParam();
  const context_t&                              context   = test_case.context;
  const pucch_processor::format4_configuration& config    = context.config;

  // Prepare resource grid.
  resource_grid_reader_spy grid(16, 14, MAX_NOF_PRBS);
  grid.write(test_case.grid.read());

  // Make sure configuration is valid.
  ASSERT_TRUE(validator->is_valid(config));

  // Process PUCCH.
  pucch_processor_result result = processor->process(grid, config);

  // Assert expected UCI payload.
  ASSERT_EQ(result.message.get_status(), uci_status::valid);
  ASSERT_EQ(span<const uint8_t>(result.message.get_harq_ack_bits()), span<const uint8_t>(test_case.context.harq_ack));
  ASSERT_EQ(span<const uint8_t>(result.message.get_sr_bits()), span<const uint8_t>(test_case.context.sr));
  ASSERT_EQ(span<const uint8_t>(result.message.get_csi_part1_bits()),
            span<const uint8_t>(test_case.context.csi_part_1));
  ASSERT_EQ(span<const uint8_t>(result.message.get_csi_part2_bits()),
            span<const uint8_t>(test_case.context.csi_part_2));
}

// Creates test suite that combines all possible parameters.
INSTANTIATE_TEST_SUITE_P(PucchProcessorF4VectorTest,
                         PucchProcessorF4Fixture,
                         ::testing::ValuesIn(pucch_processor_format4_test_data));
