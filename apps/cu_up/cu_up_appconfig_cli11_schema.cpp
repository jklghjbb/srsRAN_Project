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

#include "cu_up_appconfig_cli11_schema.h"
#include "apps/services/buffer_pool/buffer_pool_appconfig_cli11_schema.h"
#include "apps/services/logger/logger_appconfig_cli11_schema.h"
#include "cu_up_appconfig.h"
#include "srsran/support/cli11_utils.h"
#include "CLI/CLI11.hpp"

using namespace srsran;

static void configure_cli11_nru_args(CLI::App& app, srs_cu::cu_nru_appconfig& nru_cfg)
{
  add_option(app,
             "--bind_addr",
             nru_cfg.bind_addr,
             "Default local IP address interfaces bind to, unless a specific bind address is specified")
      ->check(CLI::ValidIPV4);
  app.add_option(
      "--ext_addr", nru_cfg.ext_addr, "External IP address that is advertised to receive F1-U packets from the DU");
  add_option(app, "--udp_max_rx_msgs", nru_cfg.udp_rx_max_msgs, "Maximum amount of messages RX in a single syscall");
  add_option(app,
             "--pool_threshold",
             nru_cfg.pool_occupancy_threshold,
             "Pool occupancy threshold after which packets are dropped")
      ->check(CLI::Range(0.0, 1.0));
  ;
}

static void configure_cli11_e1ap_args(CLI::App& app, srs_cu::cu_up_e1ap_appconfig& e1ap_cfg)
{
  add_option(app,
             "--addr",
             e1ap_cfg.addr,
             "sctp server that e1 client connects to")
      ->check(CLI::ValidIPV4);
  add_option(app,
             "--port",
              e1ap_cfg.port,
             "Pool occupancy threshold after which packets are dropped")  ;
}

void srsran::configure_cli11_with_cu_appconfig_schema(CLI::App& app, srs_cu::cu_up_appconfig& cu_cfg)
{
  // Logging section.
  configure_cli11_with_logger_appconfig_schema(app, cu_cfg.log_cfg);

  // Buffer pool section.
  configure_cli11_with_buffer_pool_appconfig_schema(app, cu_cfg.buffer_pool_config);

  // NR-U section.
  CLI::App* cu_up_subcmd = add_subcommand(app, "cu_up", "CU-UP parameters")->configurable();
  CLI::App* nru_subcmd   = add_subcommand(*cu_up_subcmd, "nru", "NR-U parameters")->configurable();
  CLI::App* e1ap_subcmd   = add_subcommand(*cu_up_subcmd, "e1ap", "NR-U parameters")->configurable();
  configure_cli11_nru_args(*nru_subcmd, cu_cfg.nru_cfg);
  configure_cli11_e1ap_args(*e1ap_subcmd, cu_cfg.e1_client_cfg);
}
