/*
 *
 * Copyright 2021-2023 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#include "lib/e2/common/e2ap_asn1_packer.h"
#include "lib/e2/common/e2ap_asn1_utils.h"
#include "tests/unittests/e2/common/e2_test_helpers.h"
#include "srsran/support/async/async_test_utils.h"
#include "srsran/support/test_utils.h"
#include <gtest/gtest.h>

using namespace srsran;
/// Test successful cu-cp initiated e2 setup procedure
TEST_F(e2_test, when_e2_subscription_request_correct_sent_subscription_response)
{
  using namespace asn1::e2ap;
  // Action 1: Create valid e2 message
  uint8_t e2ap_sub_req[] = {0x00, 0x08, 0x40, 0x2b, 0x00, 0x00, 0x03, 0x00, 0x1d, 0x00, 0x05, 0x00,
                            0x00, 0x7b, 0x00, 0x15, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x1e,
                            0x00, 0x15, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x13, 0x40,
                            0x0a, 0x60, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x00};

  byte_buffer e2ap_sub_req_buf(e2ap_sub_req, e2ap_sub_req + sizeof(e2ap_sub_req));
  packer->handle_packed_pdu(std::move(e2ap_sub_req_buf));

  asn1::cbit_ref bref(gw->last_pdu);
  e2_message     msg = {};
  if (msg.pdu.unpack(bref) != asn1::SRSASN_SUCCESS) {
    printf("Couldn't unpack E2 PDU");
  }
  ASSERT_EQ(msg.pdu.type().value, asn1::e2ap::e2_ap_pdu_c::types_opts::successful_outcome);
}
TEST_F(e2_test_subscriber, when_e2_subscription_request_received_start_indication_procedure)
{
  using namespace asn1::e2ap;
  // Action 1: Create valid e2 message
  uint8_t e2ap_sub_req[] = {0x00, 0x08, 0x40, 0x2b, 0x00, 0x00, 0x03, 0x00, 0x1d, 0x00, 0x05, 0x00,
                            0x00, 0x7b, 0x00, 0x15, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x1e,
                            0x00, 0x15, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x13, 0x40,
                            0x0a, 0x60, 0x01, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04, 0x02, 0x00};

  byte_buffer e2ap_sub_req_buf(e2ap_sub_req, e2ap_sub_req + sizeof(e2ap_sub_req));
  packer->handle_packed_pdu(std::move(e2ap_sub_req_buf));
  asn1::cbit_ref bref(gw->last_pdu);
  e2_message     msg = {};
  if (msg.pdu.unpack(bref) != asn1::SRSASN_SUCCESS) {
    printf("Couldn't unpack E2 PDU");
  }
  ASSERT_EQ(msg.pdu.type().value, asn1::e2ap::e2_ap_pdu_c::types_opts::successful_outcome);
  for (int i = 0; i < 1500; i++) {
    this->tick();
  }
  asn1::cbit_ref bref1(gw->last_pdu);
  e2_message     msg1 = {};
  if (msg1.pdu.unpack(bref1) != asn1::SRSASN_SUCCESS) {
    printf("Couldn't unpack E2 PDU");
  }

  if (msg1.pdu.init_msg().value.type() == e2_ap_elem_procs_o::init_msg_c::types_opts::ri_cind) {
    printf("Received RIC Indication\n");
  }
}
