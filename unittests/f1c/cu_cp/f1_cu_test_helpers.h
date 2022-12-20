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

#include "../common/test_helpers.h"
#include "unittests/f1c/common/f1_cu_test_messages.h"
#include "srsgnb/cu_cp/cu_cp_types.h"
#include "srsgnb/f1c/common/f1c_common.h"
#include "srsgnb/f1c/cu_cp/f1ap_cu.h"
#include "srsgnb/f1c/cu_cp/f1ap_cu_factory.h"
#include <gtest/gtest.h>

namespace srsgnb {
namespace srs_cu_cp {

/// Reusable notifier class that a) stores the received du_index for test inspection and b)
/// calls the registered DU handler (if any). The handler can be added upon construction
/// or later via the attach_handler() method.
class dummy_f1c_du_management_notifier : public f1c_du_management_notifier
{
public:
  void attach_handler(cu_cp_du_handler* handler_) { handler = handler_; };
  void on_du_remove_request_received(du_index_t idx) override
  {
    logger.info("Received a du remove request for du {}", idx);
    last_du_idx = idx; // store idx

    if (handler != nullptr) {
      logger.info("Forwarding remove request");
      handler->handle_du_remove_request(idx);
    }
  }

  du_index_t last_du_idx;

private:
  srslog::basic_logger& logger  = srslog::fetch_basic_logger("TEST");
  cu_cp_du_handler*     handler = nullptr;
};

/// Fixture class for F1AP
class f1ap_cu_test : public ::testing::Test
{
protected:
  f1ap_cu_test();
  ~f1ap_cu_test() override;

  srslog::basic_logger& f1ap_logger = srslog::fetch_basic_logger("F1AP");
  srslog::basic_logger& test_logger = srslog::fetch_basic_logger("TEST");

  dummy_f1c_pdu_notifier           f1c_pdu_notifier;
  dummy_f1c_du_processor_notifier  du_processor_notifier;
  dummy_f1c_du_management_notifier f1c_du_mgmt_notifier;
  std::unique_ptr<f1ap_cu>         f1c;
};

} // namespace srs_cu_cp
} // namespace srsgnb