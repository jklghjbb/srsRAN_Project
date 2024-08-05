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

#include "srsran/adt/byte_buffer.h"
#include "srsran/adt/optional.h"
#include "srsran/f1ap/common/ue_context_config.h"
#include "srsran/pdcp/pdcp_sn_size.h"
#include "srsran/ran/du_types.h"
#include "srsran/ran/five_qi.h"
#include "srsran/ran/qos/qos_info.h"
#include "srsran/ran/rnti.h"
#include "srsran/ran/s_nssai.h"

namespace srsran {
namespace srs_du {

/// \brief F1AP sends this request to the DU to create a new UE context. This happens in the particular case
/// of a F1AP UE Context Setup Request received without associated logical F1-connection.
struct f1ap_ue_context_creation_request {
  du_ue_index_t   ue_index;
  du_cell_index_t pcell_index;
};

/// \brief Response from the DU back to the F1AP with the created UE index.
struct f1ap_ue_context_creation_response {
  bool result;
  /// C-RNTI allocated during the UE creation, that the F1AP can send to the CU-CP in its response.
  rnti_t crnti;
};

/// \brief DRB to be setup or modified in the UE context.
struct f1ap_drb_setup_request : public f1ap_drb_to_setup {
  five_qi_t five_qi;
  uint8_t   arp_priority_level;
  s_nssai_t s_nssai;
  /// GBR flow information is present only for GBR QoS flows. See TS 38.473, clause 9.3.1.45.
  std::optional<gbr_qos_info_t> gbr_flow_info;
};

/// \brief SCell to be setup in the UE context.
struct f1ap_scell_to_setup {
  serv_cell_index_t serv_cell_index;
  du_cell_index_t   cell_index;
};

/// \brief Request from DU F1AP to DU manager to modify existing UE configuration.
struct f1ap_ue_context_update_request {
  du_ue_index_t         ue_index;
  std::vector<srb_id_t> srbs_to_setup;
  /// List of new DRBs to setup.
  std::vector<f1ap_drb_setup_request> drbs_to_setup;
  /// List of DRBs to modify.
  std::vector<f1ap_drb_to_modify> drbs_to_mod;
  /// List of DRBs to remove.
  std::vector<drb_id_t>            drbs_to_rem;
  std::vector<f1ap_scell_to_setup> scells_to_setup;
  std::vector<serv_cell_index_t>   scells_to_rem;
  /// \brief If true, the gnb-DU shall generate a cell group configuration using full configuration. Otherwise, delta,
  /// should be used.
  bool full_config_required;
  /// \brief Optional HO preparation information. If present, the gnb-DU shall proceed with a reconfiguration with sync
  /// as defined in TS 38.331, and TS 38.473, 8.3.1.2.
  byte_buffer ho_prep_info;
  /// \brief If a source cell group config is included, the gnb-DU shall generate a cell group configuration using
  /// full configuration. Otherwise, delta configuration is allowed, as per TS 38.473, 8.3.1.2.
  byte_buffer source_cell_group_cfg;
};

/// \brief Response from DU manager to DU F1AP with the result of the UE context update.
struct f1ap_ue_context_update_response {
  bool result;
  /// List of DRBs that were successfully setup.
  std::vector<f1ap_drb_setupmod> drbs_setup;
  /// List of DRBs that were successfully modified.
  std::vector<f1ap_drb_setupmod> drbs_mod;
  /// List of DRBs that failed to be setup.
  std::vector<f1ap_drb_failed_to_setupmod> failed_drbs_setups;
  /// List of DRBs that failed to be modified.
  std::vector<f1ap_drb_failed_to_setupmod> failed_drb_mods;
  byte_buffer                              du_to_cu_rrc_container;
  bool                                     full_config_present = false;
};

/// \brief Handled causes for RLF.
enum class rlf_cause { max_mac_kos_reached, max_rlc_retxs_reached, rlc_protocol_failure };

/// \brief Request Command for F1AP UE CONTEXT Release Request.
struct f1ap_ue_context_release_request {
  du_ue_index_t ue_index;
  rlf_cause     cause;
};

/// \brief Request Command for F1AP UE CONTEXT Modification Required.
struct f1ap_ue_context_modification_required {};

} // namespace srs_du
} // namespace srsran
