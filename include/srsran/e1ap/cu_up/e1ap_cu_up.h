/*
 *
 * Copyright 2021-2023 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#pragma once

#include "../common/e1ap_types.h"
#include "e1ap_cu_up_bearer_context_update.h"
#include "srsran/adt/expected.h"
#include "srsran/cu_up/cu_up_types.h"
#include "srsran/e1ap/common/e1_setup_messages.h"
#include "srsran/e1ap/common/e1ap_common.h"
#include "srsran/support/async/async_task.h"

namespace srsran {
namespace srs_cu_up {

/// Handle E1AP interface management procedures as defined in TS 38.463 section 8.2.
class e1ap_connection_manager
{
public:
  virtual ~e1ap_connection_manager() = default;

  /// \brief Connect the CU-UP to CU-CP via E1AP interface.
  virtual SRSRAN_NODISCARD bool connect_to_cu_cp() = 0;

  /// \brief Initiates the E1 Setup procedure as per TS 38.463, Section 8.2.3.
  /// \param[in] request The E1SetupRequest message to transmit.
  /// \return Returns a cu_up_e1_setup_response struct with the success member set to 'true' in case of a
  /// successful outcome, 'false' otherwise. \remark The CU-UP transmits the E1SetupRequest as per TS 38.463
  /// section 8.2.3 and awaits the response. If a E1SetupFailure is received the E1AP will handle the failure.
  virtual async_task<cu_up_e1_setup_response> handle_cu_up_e1_setup_request(const cu_up_e1_setup_request& request) = 0;
};

/// Handle E1AP control messages
class e1ap_control_message_handler
{
public:
  virtual ~e1ap_control_message_handler() = default;

  /// \brief Initiates the Bearer Context Inactivity Notification procedure as defined in TS 38.463 section 8.6.3.
  /// \param[in] msg The common type bearer context inactivity notification message to convert and forward to the CU-CP.
  virtual void
  handle_bearer_context_inactivity_notification(const e1ap_bearer_context_inactivity_notification& msg) = 0;
};

/// Methods used by E1AP to notify the CU-UP.
class e1ap_cu_up_notifier
{
public:
  virtual ~e1ap_cu_up_notifier() = default;

  /// \brief Notifies the UE manager to create a UE context.
  /// \param[in] msg The received bearer context setup message.
  /// \return Returns a bearer context response message containing the index of the created UE context.
  virtual e1ap_bearer_context_setup_response
  on_bearer_context_setup_request_received(const e1ap_bearer_context_setup_request& msg) = 0;

  /// \brief Notifies the UE manager to create a UE context.
  /// \param[in] msg The received bearer context modification message.
  /// \return Returns a bearer context response message containing the index of the created UE context.
  virtual e1ap_bearer_context_modification_response
  on_bearer_context_modification_request_received(const e1ap_bearer_context_modification_request& msg) = 0;

  /// \brief Notifies the UE manager to release a UE context.
  /// \param[in] msg The received bearer context release command.
  virtual void on_bearer_context_release_command_received(const e1ap_bearer_context_release_command& msg) = 0;
};

/// \brief Interface to query statistics from the E1AP interface.
class e1ap_statistics_handler
{
public:
  virtual ~e1ap_statistics_handler() = default;

  /// \brief Get the number of UEs registered at the E1AP.
  /// \return The number of UEs.
  virtual size_t get_nof_ues() const = 0;
};

/// Combined entry point for E1AP handling.
class e1ap_interface : public e1ap_message_handler,
                       public e1ap_control_message_handler,
                       public e1ap_event_handler,
                       public e1ap_connection_manager,
                       public e1ap_statistics_handler
{
public:
  virtual ~e1ap_interface() = default;
};

} // namespace srs_cu_up
} // namespace srsran
