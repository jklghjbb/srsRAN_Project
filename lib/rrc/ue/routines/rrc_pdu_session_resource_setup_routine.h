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

#include "../procedures/rrc_ue_event_manager.h"
#include "../rrc_ue_context.h"
#include "srsgnb/asn1/rrc_nr/rrc_nr.h"
#include "srsgnb/rrc/rrc_du.h"
#include "srsgnb/rrc/rrc_ue.h"
#include "srsgnb/support/async/async_task.h"
#include "srsgnb/support/async/eager_async_task.h"

namespace srsgnb {
namespace srs_cu_cp {

/// \brief Handles the setup of PDU session resources from the RRC viewpoint.
/// TODO Add seqdiag
class rrc_pdu_session_resource_setup_routine
{
public:
  rrc_pdu_session_resource_setup_routine(rrc_ue_context_t&                     context_,
                                         rrc_ue_reconfiguration_proc_notifier& rrc_ue_notifier_,
                                         rrc_ue_event_manager&                 ev_mng_,
                                         srslog::basic_logger&                 logger_);

  void operator()(coro_context<async_task<bool>>& ctx);

  static const char* name() { return "RRC PDU Session Creation Routine"; }

private:
  drb_context drb_to_add;
  drb_context allocate_new_drb();

  rrc_ue_context_t                      context;
  rrc_ue_reconfiguration_proc_notifier& rrc_ue_notifier;
  rrc_ue_event_manager&                 event_mng; // event manager for the RRC UE entity
  srslog::basic_logger&                 logger;

  bool procedure_result = false;
};

} // namespace srs_cu_cp
} // namespace srsgnb