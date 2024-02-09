/*
 *
 * Copyright 2021-2024 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#include "cu_cp_test_environment.h"
#include "tests/unittests/cu_cp/cu_cp_test_helpers.h"
#include "tests/unittests/e1ap/common/e1ap_cu_cp_test_messages.h"
#include "tests/unittests/f1ap/common/f1ap_cu_test_messages.h"
#include "tests/unittests/ngap/ngap_test_messages.h"
#include "srsran/asn1/f1ap/f1ap_pdu_contents_ue.h"
#include "srsran/asn1/rrc_nr/msg_common.h"
#include "srsran/e1ap/common/e1ap_message.h"
#include "srsran/f1ap/common/f1ap_message.h"
#include "srsran/ngap/ngap_message.h"
#include <gtest/gtest.h>

using namespace srsran;
using namespace srs_cu_cp;

class cu_cp_connectivity_test : public cu_cp_test_environment, public ::testing::Test
{
public:
  cu_cp_connectivity_test() : cu_cp_test_environment(cu_cp_test_env_params{8, 8, create_mock_amf()}) {}
};

//----------------------------------------------------------------------------------//
// CU-CP to AMF connection handling                                                 //
//----------------------------------------------------------------------------------//

TEST_F(cu_cp_connectivity_test, when_cu_cp_is_created_then_it_is_not_connected_to_amf)
{
  ngap_message ngap_pdu;
  ASSERT_FALSE(get_amf().try_pop_rx_pdu(ngap_pdu))
      << "The CU-CP should not send a message to the NG interface before being started";

  ASSERT_FALSE(get_cu_cp().get_cu_cp_ngap_connection_interface().amf_is_connected());
}

TEST_F(cu_cp_connectivity_test, when_cu_cp_starts_then_it_initiates_ng_setup_procedure_and_blocks_waiting_for_response)
{
  // Enqueue AMF NG Setup Response as an auto-reply to CU-CP.
  ngap_message ng_setup_resp = generate_ng_setup_response();
  get_amf().enqueue_next_tx_pdu(ng_setup_resp);

  // This call is blocking. When it returns, the CU-CP should have finished its attempt at AMF connection.
  ASSERT_TRUE(get_cu_cp().start());

  ngap_message ngap_pdu;
  ASSERT_TRUE(get_amf().try_pop_rx_pdu(ngap_pdu)) << "CU-CP did not send the NG Setup Request to the AMF";
  ASSERT_TRUE(is_pdu_type(ngap_pdu, asn1::ngap::ngap_elem_procs_o::init_msg_c::types::ng_setup_request))
      << "CU-CP did not setup the AMF connection";

  ASSERT_TRUE(get_cu_cp().get_cu_cp_ngap_connection_interface().amf_is_connected());
}

TEST_F(cu_cp_connectivity_test, when_ng_setup_fails_then_cu_cp_is_not_in_amf_connected_state)
{
  // Enqueue AMF NG Setup Response as an auto reply to CU-CP.
  ngap_message ng_setup_fail = generate_ng_setup_failure();
  get_amf().enqueue_next_tx_pdu(ng_setup_fail);

  // This call is blocking. When it returns, the CU-CP should have finished its attempt at AMF connection.
  ASSERT_FALSE(get_cu_cp().start());

  ngap_message ngap_pdu;
  ASSERT_TRUE(get_amf().try_pop_rx_pdu(ngap_pdu)) << "CU-CP did not send the NG Setup Request to the AMF";
  ASSERT_TRUE(is_pdu_type(ngap_pdu, asn1::ngap::ngap_elem_procs_o::init_msg_c::types::ng_setup_request))
      << "CU-CP did not setup the AMF connection";

  ASSERT_FALSE(get_cu_cp().get_cu_cp_ngap_connection_interface().amf_is_connected());
}

//----------------------------------------------------------------------------------//
// DU connection handling                                                           //
//----------------------------------------------------------------------------------//

TEST_F(cu_cp_connectivity_test, when_new_f1_setup_request_is_received_and_ng_is_setup_then_f1_setup_is_accepted)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Establish TNL connection between DU and CU-CP.
  auto ret = connect_new_du();
  ASSERT_TRUE(ret.has_value());
  unsigned du_idx = *ret;

  // Send F1 Setup Request.
  get_du(du_idx).push_tx_pdu(generate_f1_setup_request());

  // Ensure the F1 Setup Response is received and correct.
  f1ap_message f1ap_pdu;
  ASSERT_TRUE(this->wait_for_f1ap_tx_pdu(du_idx, f1ap_pdu, std::chrono::milliseconds{1000}))
      << "F1 Setup Response was not received by the DU";
  ASSERT_EQ(f1ap_pdu.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::successful_outcome);
  ASSERT_EQ(f1ap_pdu.pdu.successful_outcome().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::successful_outcome_c::types_opts::f1_setup_resp);
}

TEST_F(cu_cp_connectivity_test, when_max_nof_dus_connected_reached_then_cu_cp_rejects_new_du_connections)
{
  for (unsigned idx = 0; idx < this->get_test_env_params().max_nof_dus; idx++) {
    auto ret = connect_new_du();
    ASSERT_TRUE(ret.has_value());
  }

  auto ret = connect_new_du();
  ASSERT_FALSE(ret.has_value());
}

TEST_F(
    cu_cp_connectivity_test,
    when_max_nof_dus_connected_reached_and_du_connection_drops_then_du_is_removed_from_cu_cp_and_new_du_connection_is_accepted)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Establish TNL connection and F1 Setup for max number of DUs.
  for (unsigned idx = 0; idx < this->get_test_env_params().max_nof_dus; idx++) {
    auto ret = connect_new_du();
    ASSERT_TRUE(ret.has_value());
    unsigned du_idx = *ret;
    get_du(du_idx).push_tx_pdu(generate_f1_setup_request());
    f1ap_message f1ap_pdu;
    ASSERT_TRUE(this->wait_for_f1ap_tx_pdu(du_idx, f1ap_pdu, std::chrono::milliseconds{1000}));
  }

  // Drop DU connection.
  ASSERT_TRUE(this->drop_du_connection(0));

  // A new DU can now be created.
  auto ret = connect_new_du();
  ASSERT_TRUE(ret.has_value());
}

TEST_F(cu_cp_connectivity_test, when_ng_setup_is_not_successful_then_f1_setup_is_rejected)
{
  // Enqueue AMF NG Setup Response as an auto reply to CU-CP.
  ngap_message ng_setup_fail = generate_ng_setup_failure();
  get_amf().enqueue_next_tx_pdu(ng_setup_fail);

  // This call is blocking. When it returns, the CU-CP should have finished its attempt at AMF connection.
  ASSERT_FALSE(get_cu_cp().start());

  // Establish TNL connection between DU and CU-CP and start F1 setup procedure.
  auto ret = connect_new_du();
  ASSERT_TRUE(ret.has_value());
  unsigned du_idx = *ret;
  get_du(du_idx).push_tx_pdu(generate_f1_setup_request());
  f1ap_message f1ap_pdu;
  ASSERT_TRUE(this->wait_for_f1ap_tx_pdu(du_idx, f1ap_pdu, std::chrono::milliseconds{1000}));

  // The CU-CP should reject F1 setup.
  ASSERT_EQ(f1ap_pdu.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::unsuccessful_outcome);
}

//----------------------------------------------------------------------------------//
// CU-UP connection handling                                                        //
//----------------------------------------------------------------------------------//

TEST_F(cu_cp_connectivity_test, when_new_e1_setup_request_is_received_and_ng_is_setup_then_e1_setup_is_accepted)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Establish TNL connection between CU-CP and CU-UP.
  auto ret = connect_new_cu_up();
  ASSERT_TRUE(ret.has_value());
  unsigned cu_up_idx = *ret;

  // CU-UP sends E1 Setup Request.
  get_cu_up(cu_up_idx).push_tx_pdu(generate_valid_cu_up_e1_setup_request());

  // Ensure the E1 Setup Response is received and correct.
  e1ap_message e1ap_pdu;
  ASSERT_TRUE(this->wait_for_e1ap_tx_pdu(cu_up_idx, e1ap_pdu, std::chrono::milliseconds{1000}))
      << "E1 Setup Response was not received by the CU-UP";
  ASSERT_EQ(e1ap_pdu.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::successful_outcome);
  ASSERT_EQ(e1ap_pdu.pdu.successful_outcome().value.type().value,
            asn1::e1ap::e1ap_elem_procs_o::successful_outcome_c::types_opts::gnb_cu_up_e1_setup_resp);
}

TEST_F(cu_cp_connectivity_test, when_max_nof_cu_ups_connected_reached_then_cu_cp_rejects_new_cu_up_connections)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Establish TNL connection between CU-CP and CU-UP.
  for (unsigned i = 0; i != this->get_test_env_params().max_nof_cu_ups; ++i) {
    auto ret = connect_new_cu_up();
    ASSERT_TRUE(ret.has_value());
  }

  // The last one is rejected.
  auto ret = connect_new_cu_up();
  ASSERT_FALSE(ret.has_value());
}

TEST_F(
    cu_cp_connectivity_test,
    when_max_nof_cu_ups_connected_reached_and_cu_up_connection_drops_then_cu_up_is_removed_from_cu_cp_and_new_cu_up_connection_is_accepted)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Establish TNL connection and E1 Setup for max number of CU-UPs.
  for (unsigned idx = 0; idx < this->get_test_env_params().max_nof_dus; idx++) {
    auto ret = connect_new_cu_up();
    ASSERT_TRUE(ret.has_value());
    unsigned cu_up_idx = *ret;
    get_cu_up(cu_up_idx).push_tx_pdu(generate_valid_cu_up_e1_setup_request());
    e1ap_message e1ap_pdu;
    ASSERT_TRUE(this->wait_for_e1ap_tx_pdu(cu_up_idx, e1ap_pdu, std::chrono::milliseconds{1000}));
  }

  // Drop DU connection.
  ASSERT_TRUE(this->drop_cu_up_connection(0));

  // A new CU-UP can now be created.
  auto ret = connect_new_cu_up();
  ASSERT_TRUE(ret.has_value());
}

//----------------------------------------------------------------------------------//
//  UE connection handling                                                          //
//----------------------------------------------------------------------------------//

TEST_F(cu_cp_connectivity_test, when_ng_f1_e1_are_setup_then_ues_can_attach)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Setup DU.
  auto ret = connect_new_du();
  ASSERT_TRUE(ret.has_value());
  unsigned du_idx = ret.value();
  ASSERT_TRUE(this->run_f1_setup(du_idx));

  // Setup CU-UP.
  ret = connect_new_cu_up();
  ASSERT_TRUE(ret.has_value());
  unsigned cu_up_idx = ret.value();
  ASSERT_TRUE(this->run_f1_setup(cu_up_idx));

  // Check no UEs.
  auto report = this->get_cu_cp().get_metrics_handler().request_metrics_report();
  ASSERT_TRUE(report.ue_metrics.ues.empty());

  // Create UE by sending Initial UL RRC Message.
  gnb_du_ue_f1ap_id_t du_ue_f1ap_id = int_to_gnb_du_ue_f1ap_id(0);
  rnti_t              crnti         = to_rnti(0x4601);
  get_du(du_idx).push_tx_pdu(generate_init_ul_rrc_message_transfer(du_ue_f1ap_id, crnti));

  // Verify F1AP DL RRC Message is sent with RRC Setup.
  f1ap_message f1ap_pdu;
  ASSERT_TRUE(this->wait_for_f1ap_tx_pdu(du_idx, f1ap_pdu));
  ASSERT_EQ(f1ap_pdu.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(f1ap_pdu.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::dl_rrc_msg_transfer);
  const auto& dl_rrc_msg = f1ap_pdu.pdu.init_msg().value.dl_rrc_msg_transfer();
  ASSERT_EQ(int_to_gnb_du_ue_f1ap_id(dl_rrc_msg->gnb_du_ue_f1ap_id), du_ue_f1ap_id);
  ASSERT_EQ(int_to_srb_id(dl_rrc_msg->srb_id), srb_id_t::srb0);
  gnb_cu_ue_f1ap_id_t         cu_ue_f1ap_id = int_to_gnb_cu_ue_f1ap_id(dl_rrc_msg->gnb_cu_ue_f1ap_id);
  asn1::rrc_nr::dl_ccch_msg_s ccch;
  {
    asn1::cbit_ref bref{dl_rrc_msg->rrc_container};
    ASSERT_EQ(ccch.unpack(bref), asn1::SRSASN_SUCCESS);
  }
  ASSERT_EQ(ccch.msg.c1().type().value, asn1::rrc_nr::dl_ccch_msg_type_c::c1_c_::types_opts::rrc_setup);

  // Check UE is created.
  report = this->get_cu_cp().get_metrics_handler().request_metrics_report();
  ASSERT_EQ(report.ue_metrics.ues.size(), 1);
  ASSERT_EQ(report.ue_metrics.ues[0].rnti, crnti);

  // AMF still not notified of UE attach.
  ngap_message ngap_pdu;
  ASSERT_FALSE(this->get_amf().try_pop_rx_pdu(ngap_pdu));

  // UE sends UL RRC Message with RRC Setup Complete.
  f1ap_message ul_rrc_msg =
      generate_ul_rrc_message_transfer(cu_ue_f1ap_id, du_ue_f1ap_id, srb_id_t::srb1, generate_rrc_setup_complete());
  test_logger.info("Injecting UL RRC message (RRC Setup Complete)");
  get_du(du_idx).push_tx_pdu(ul_rrc_msg);

  ASSERT_TRUE(this->wait_for_ngap_tx_pdu(ngap_pdu));
  ASSERT_TRUE(is_pdu_type(ngap_pdu, asn1::ngap::ngap_elem_procs_o::init_msg_c::types::types_opts::init_ue_msg));
}

TEST_F(cu_cp_connectivity_test, when_e1_is_not_setup_then_new_ues_are_rejected)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Setup DU.
  auto ret = connect_new_du();
  ASSERT_TRUE(ret.has_value());
  unsigned du_idx = ret.value();
  ASSERT_TRUE(this->run_f1_setup(du_idx));

  // Send Initial UL RRC Message.
  gnb_du_ue_f1ap_id_t ue_f1ap_id = int_to_gnb_du_ue_f1ap_id(0);
  rnti_t              crnti      = to_rnti(0x4601);
  get_du(du_idx).push_tx_pdu(generate_init_ul_rrc_message_transfer(ue_f1ap_id, crnti));

  // Verify F1AP DL RRC Message is sent with RRC Setup.
  f1ap_message f1ap_pdu;
  ASSERT_TRUE(this->wait_for_f1ap_tx_pdu(du_idx, f1ap_pdu, std::chrono::milliseconds{1000}));
  ASSERT_EQ(f1ap_pdu.pdu.type().value, asn1::f1ap::f1ap_pdu_c::types_opts::init_msg);
  ASSERT_EQ(f1ap_pdu.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::ue_context_release_cmd);
  const auto& ue_rel = f1ap_pdu.pdu.init_msg().value.ue_context_release_cmd();
  ASSERT_EQ(int_to_gnb_du_ue_f1ap_id(ue_rel->gnb_du_ue_f1ap_id), ue_f1ap_id);
  ASSERT_TRUE(ue_rel->srb_id_present);
  ASSERT_EQ(int_to_srb_id(ue_rel->srb_id), srb_id_t::srb0);
  asn1::rrc_nr::dl_ccch_msg_s ccch;
  {
    asn1::cbit_ref bref{ue_rel->rrc_container};
    ASSERT_EQ(ccch.unpack(bref), asn1::SRSASN_SUCCESS);
  }
  ASSERT_EQ(ccch.msg.c1().type().value, asn1::rrc_nr::dl_ccch_msg_type_c::c1_c_::types_opts::rrc_reject);

  // Check UE is created and is only destroyed when F1AP UE context release complete is received.
  auto report = this->get_cu_cp().get_metrics_handler().request_metrics_report();
  ASSERT_EQ(report.ue_metrics.ues.size(), 1);
  ASSERT_EQ(report.ue_metrics.ues[0].rnti, crnti);

  // Send F1AP UE Context Release Complete.
  auto rel_complete =
      generate_ue_context_release_complete(int_to_gnb_cu_ue_f1ap_id(ue_rel->gnb_cu_ue_f1ap_id), ue_f1ap_id);
  get_du(du_idx).push_tx_pdu(rel_complete);

  // Verify UE is removed.
  report = this->get_cu_cp().get_metrics_handler().request_metrics_report();
  ASSERT_TRUE(report.ue_metrics.ues.empty());

  // Verify no NGAP PDU was sent when a UE is rejected.
  ngap_message ngap_pdu;
  ASSERT_FALSE(this->get_amf().try_pop_rx_pdu(ngap_pdu));
}

TEST_F(cu_cp_connectivity_test, when_initial_ul_rrc_message_has_no_rrc_container_then_ue_is_rejected)
{
  // Run NG setup to completion.
  run_ng_setup();

  // Setup DU.
  auto ret = connect_new_du();
  ASSERT_TRUE(ret.has_value());
  unsigned du_idx = ret.value();
  ASSERT_TRUE(this->run_f1_setup(du_idx));

  // Setup CU-UP.
  ret = connect_new_cu_up();
  ASSERT_TRUE(ret.has_value());
  unsigned cu_up_idx = ret.value();
  ASSERT_TRUE(this->run_f1_setup(cu_up_idx));

  // Send Initial UL RRC Message without DU-to-CU-RRC container.
  gnb_du_ue_f1ap_id_t du_ue_f1ap_id = int_to_gnb_du_ue_f1ap_id(0);
  rnti_t              crnti         = to_rnti(0x4601);
  f1ap_message        init_rrc_msg  = generate_init_ul_rrc_message_transfer(du_ue_f1ap_id, crnti);
  init_rrc_msg.pdu.init_msg().value.init_ul_rrc_msg_transfer()->du_to_cu_rrc_container_present = false;
  get_du(du_idx).push_tx_pdu(init_rrc_msg);

  // Verify CU-CP sends a UE Context Release command over SRB0.
  f1ap_message f1ap_pdu;
  ASSERT_TRUE(this->wait_for_f1ap_tx_pdu(du_idx, f1ap_pdu));
  ASSERT_EQ(f1ap_pdu.pdu.type(), asn1::f1ap::f1ap_pdu_c::types_opts::options::init_msg);
  ASSERT_EQ(f1ap_pdu.pdu.init_msg().value.type().value,
            asn1::f1ap::f1ap_elem_procs_o::init_msg_c::types_opts::ue_context_release_cmd);
  const auto& ue_rel = f1ap_pdu.pdu.init_msg().value.ue_context_release_cmd();
  ASSERT_TRUE(ue_rel->rrc_container_present);
  // check that the SRB ID is set if the RRC Container is included
  ASSERT_TRUE(ue_rel->srb_id_present);
  ASSERT_EQ(ue_rel->srb_id, 0);

  // Verify that the UE Context Release command contains an RRC Reject.
  asn1::rrc_nr::dl_ccch_msg_s ccch;
  {
    asn1::cbit_ref bref{f1ap_pdu.pdu.init_msg().value.ue_context_release_cmd()->rrc_container};
    ASSERT_EQ(ccch.unpack(bref), asn1::SRSASN_SUCCESS);
  }
  ASSERT_EQ(ccch.msg.c1().type().value, asn1::rrc_nr::dl_ccch_msg_type_c::c1_c_::types_opts::rrc_reject);

  // Verify UE is not removed until UE Context Release Complete.
  auto report = this->get_cu_cp().get_metrics_handler().request_metrics_report();
  ASSERT_EQ(report.ue_metrics.ues.size(), 1);
  ASSERT_EQ(report.ue_metrics.ues[0].rnti, to_rnti(0x4601));

  // Send F1AP UE Context Release Complete.
  auto rel_complete =
      generate_ue_context_release_complete(int_to_gnb_cu_ue_f1ap_id(ue_rel->gnb_cu_ue_f1ap_id), du_ue_f1ap_id);
  get_du(du_idx).push_tx_pdu(rel_complete);

  // Verify UE is removed.
  report = this->get_cu_cp().get_metrics_handler().request_metrics_report();
  ASSERT_TRUE(report.ue_metrics.ues.empty());
}
