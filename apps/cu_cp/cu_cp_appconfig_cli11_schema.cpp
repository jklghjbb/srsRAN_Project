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

#include "cu_cp_appconfig_cli11_schema.h"
#include "apps/services/buffer_pool/buffer_pool_appconfig_cli11_schema.h"
#include "apps/services/logger/logger_appconfig_cli11_schema.h"
#include "cu_cp_appconfig.h"
#include "srsran/support/cli11_utils.h"
#include "CLI/CLI11.hpp"

using namespace srsran;

static void configure_cli11_f1ap_args(CLI::App& app, srs_cu_cp::cu_f1ap_appconfig& f1ap_params)
{
  add_option(app, "--bind_addr", f1ap_params.bind_addr, "F1-C bind address")->capture_default_str();
}

static void configure_cli11_e1ap_args(CLI::App& app, srs_cu_cp::cu_e1ap_appconfig& e1ap_params)
{
  add_option(app, "--bind_addr", e1ap_params.bind_addr, "e1ap bind address")->capture_default_str();
  add_option(app, "--bind_port", e1ap_params.bind_port, "e1ap bind port")->capture_default_str();
}

void srsran::configure_cli11_with_cu_cp_appconfig_schema(CLI::App& app, cu_cp_appconfig& cu_cfg)
{
  // Logging section.
  configure_cli11_with_logger_appconfig_schema(app, cu_cfg.log_cfg);

  // Buffer pool section.
  configure_cli11_with_buffer_pool_appconfig_schema(app, cu_cfg.buffer_pool_config);

  // F1AP section.
  CLI::App* cu_cp_subcmd = add_subcommand(app, "cu_cp", "CU-UP parameters")->configurable();
  CLI::App* f1ap_subcmd  = add_subcommand(*cu_cp_subcmd, "f1ap", "F1AP parameters")->configurable();
  CLI::App* e1ap_subcmd = add_subcommand(*cu_cp_subcmd, "e1ap", "E1AP parameters")->configurable();
  configure_cli11_f1ap_args(*f1ap_subcmd, cu_cfg.f1ap_cfg);
  configure_cli11_e1ap_args(*e1ap_subcmd, cu_cfg.e1ap_cfg);
}
