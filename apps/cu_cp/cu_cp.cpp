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


#include "srsran/support/backtrace.h"
#include "srsran/support/config_parsers.h"
#include "srsran/support/cpu_features.h"
#include "srsran/support/error_handling.h"
#include "srsran/support/event_tracing.h"
#include "srsran/support/io/io_broker.h"
#include "srsran/support/io/io_broker_factory.h"
#include "srsran/support/io/io_timer_source.h"
#include "srsran/support/signal_handling.h"
#include "srsran/support/sysinfo.h"
#include "srsran/support/timers.h"
#include "srsran/support/versioning/build_info.h"
#include "srsran/support/versioning/version.h"


// cu_cp config
#include "apps/units/cu_cp/cu_cp_application_unit.h"
#include "apps/units/cu_cp/cu_cp_config_translators.h"
#include "apps/units/cu_cp/cu_cp_unit_config.h"
#include "apps/units/cu_cp/pcap_factory.h"


#include "apps/services/application_message_banners.h"
#include "apps/services/application_tracer.h"
#include "apps/services/buffer_pool/buffer_pool_manager.h"
#include "apps/services/stdin_command_dispatcher.h"
#include "apps/services/worker_manager.h"
#include "apps/services/worker_manager_config.h"


// app config
#include "apps/gnb/gnb_appconfig_translators.h"
#include "apps/cu_cp/cu_cp_appconfig_cli11_schema.h"
#include "cu_cp_appconfig.h"
#include "cu_cp_appconfig_validator.h"
#include "cu_cp_appconfig_yaml_writer.h"

// gateway and interface
#include "apps/cu/adapters/e2_gateways.h"
#include "srsran/f1ap/gateways/f1c_network_server_factory.h"
#include "srsran/pcap/dlt_pcap.h"
#include "srsran/e1ap/gateways/e1_local_connector_factory.h"
#include "srsran/ngap/gateways/n2_connection_client_factory.h"

#include <atomic>
#include <thread>

using namespace srsran;

/// \file
/// \brief Application of a Central Unit Control (CU) with combined CU control-plane (CU-CP).

static std::string config_file;

/// Flag that indicates if the application is running or being shutdown.
static std::atomic<bool> is_app_running = {true};
/// Maximum number of configuration files allowed to be concatenated in the command line.
static constexpr unsigned MAX_CONFIG_FILES = 10;

static void populate_cli11_generic_args(CLI::App& app)
{
  fmt::memory_buffer buffer;
  format_to(buffer, "srsRAN 5G CU-CP version {} ({})", get_version(), get_build_hash());
  app.set_version_flag("-v,--version", srsran::to_c_str(buffer));
  app.set_config("-c,", config_file, "Read config from file", false)->expected(1, MAX_CONFIG_FILES);
}

/// Function to call when the application is interrupted.
static void interrupt_signal_handler()
{
  is_app_running = false;
}

/// Function to call when the application is going to be forcefully shutdown.
static void cleanup_signal_handler()
{
  srslog::flush();
}

/// Function to call when an error is reported by the application.
static void app_error_report_handler()
{
  srslog::flush();
}

static void initialize_log(const std::string& filename)
{
  srslog::sink* log_sink = (filename == "stdout") ? srslog::create_stdout_sink() : srslog::create_file_sink(filename);
  if (log_sink == nullptr) {
    report_error("Could not create application main log sink.\n");
  }
  srslog::set_default_sink(*log_sink);
  srslog::init();
}

static void register_app_logs(const logger_appconfig& log_cfg,
                              cu_cp_application_unit& cu_cp_app_unit)
{
  // Set log-level of app and all non-layer specific components to app level.
  for (const auto& id : {"ALL", "SCTP-GW", "IO-EPOLL", "UDP-GW", "PCAP"}) {
    auto& logger = srslog::fetch_basic_logger(id, false);
    logger.set_level(log_cfg.lib_level);
    logger.set_hex_dump_max_size(log_cfg.hex_max_size);
  }

  auto& app_logger = srslog::fetch_basic_logger("CU-CP", false);
  app_logger.set_level(srslog::basic_levels::info);
  app_services::application_message_banners::log_build_info(app_logger);
  app_logger.set_level(log_cfg.config_level);
  app_logger.set_hex_dump_max_size(log_cfg.hex_max_size);

  auto& config_logger = srslog::fetch_basic_logger("CONFIG", false);
  config_logger.set_level(log_cfg.config_level);
  config_logger.set_hex_dump_max_size(log_cfg.hex_max_size);

  auto& metrics_logger = srslog::fetch_basic_logger("METRICS", false);
  metrics_logger.set_level(log_cfg.metrics_level);
  metrics_logger.set_hex_dump_max_size(log_cfg.hex_max_size);

  // Register units logs.
  cu_cp_app_unit.on_loggers_registration();
}

static void fill_cu_worker_manager_config(worker_manager_config& config, const cu_appconfig& unit_cfg)
{
  config.nof_low_prio_threads  = unit_cfg.expert_execution_cfg.threads.non_rt_threads.nof_non_rt_threads;
  config.low_prio_sched_config = unit_cfg.expert_execution_cfg.affinities.low_priority_cpu_cfg;
}

int main(int argc, char** argv)
{
  // Set the application error handler.
  set_error_handler(app_error_report_handler);

  static constexpr std::string_view app_name = "CU-CP";
  app_services::application_message_banners::announce_app_and_version(app_name);

  // Set interrupt and cleanup signal handlers.
  register_interrupt_signal_handler(interrupt_signal_handler);
  register_cleanup_signal_handler(cleanup_signal_handler);

  // Enable backtrace.
  enable_backtrace();

  // Setup and configure config parsing.
  CLI::App app("srsCU-CP application");
  app.config_formatter(create_yaml_config_parser());
  app.allow_config_extras(CLI::config_extras_mode::error);
  // Fill the generic application arguments to parse.
  populate_cli11_generic_args(app);

  // Configure CLI11 with the CU application configuration schema.
  cu_appconfig cu_cfg;
  configure_cli11_with_cu_appconfig_schema(app, cu_cfg);

  auto cu_cp_app_unit = create_cu_cp_application_unit("cu-cp");
  cu_cp_app_unit->on_parsing_configuration_registration(app);

  // Set the callback for the app calling all the autoderivation functions.
  app.callback([&app, &cu_cp_app_unit]() {
    cu_cp_app_unit->on_configuration_parameters_autoderivation(app);
  });

  // Parse arguments.
  CLI11_PARSE(app, argc, argv);

  // Check the modified configuration.
  if (!validate_cu_appconfig(cu_cfg) ||
      !cu_cp_app_unit->on_configuration_validation(os_sched_affinity_bitmask::available_cpus())) {
    report_error("Invalid configuration detected.\n");
  }

  // Set up logging.
  initialize_log(cu_cfg.log_cfg.filename);
  register_app_logs(cu_cfg.log_cfg, *cu_cp_app_unit);

  // Log input configuration.
  srslog::basic_logger& config_logger = srslog::fetch_basic_logger("CONFIG");
  if (config_logger.debug.enabled()) {
    YAML::Node node;
    fill_cu_appconfig_in_yaml_schema(node, cu_cfg);
    cu_cp_app_unit->dump_config(node);
    config_logger.debug("Input configuration (all values): \n{}", YAML::Dump(node));
  } else {
    config_logger.info("Input configuration (only non-default values): \n{}", app.config_to_str(false, false));
  }

  srslog::basic_logger&            cu_cp_logger = srslog::fetch_basic_logger("CU-CP");
  app_services::application_tracer app_tracer;
  if (not cu_cfg.log_cfg.tracing_filename.empty()) {
    app_tracer.enable_tracer(cu_cfg.log_cfg.tracing_filename, cu_cp_logger);
  }

  // configure cgroups
  // TODO

  // Setup size of byte buffer pool.
  app_services::buffer_pool_manager buffer_pool_service(cu_cfg.buffer_pool_config);

  // Log CPU architecture.
  // TODO

  // Check and log included CPU features and check support by current CPU
  if (cpu_supports_included_features()) {
    cu_cp_logger.debug("Required CPU features: {}", get_cpu_feature_info());
  } else {
    // Quit here until we complete selection of the best matching implementation for the current CPU at runtime.
    cu_cp_logger.error("The CPU does not support the required CPU features that were configured during compile time: {}",
                    get_cpu_feature_info());
    report_error("The CPU does not support the required CPU features that were configured during compile time: {}\n",
                 get_cpu_feature_info());
  }

  // Check some common causes of performance issues and print a warning if required.
  check_cpu_governor(cu_cp_logger);
  check_drm_kms_polling(cu_cp_logger);

  // Create worker manager.
  worker_manager_config worker_manager_cfg;
  fill_cu_worker_manager_config(worker_manager_cfg, cu_cfg);
  cu_cp_app_unit->fill_worker_manager_config(worker_manager_cfg);
  worker_manager workers{worker_manager_cfg};

  // Create layer specific PCAPs.
  cu_cp_dlt_pcaps cu_cp_dlt_pcaps =
      create_cu_cp_dlt_pcap(cu_cp_app_unit->get_cu_cp_unit_config().pcap_cfg, *workers.get_executor_getter());
  // cu_up_dlt_pcaps cu_up_dlt_pcaps =
  //     create_cu_up_dlt_pcaps(cu_up_app_unit->get_cu_up_unit_config().pcap_cfg, *workers.get_executor_getter());

  // Create IO broker.
  const auto&                low_prio_cpu_mask = cu_cfg.expert_execution_cfg.affinities.low_priority_cpu_cfg.mask;
  io_broker_config           io_broker_cfg(low_prio_cpu_mask);
  std::unique_ptr<io_broker> epoll_broker = create_io_broker(io_broker_type::epoll, io_broker_cfg);

  // Create F1-C GW (TODO cleanup port and PPID args with factory)
  sctp_network_gateway_config f1c_sctp_cfg = {};
  f1c_sctp_cfg.if_name                     = "F1-C";
  f1c_sctp_cfg.bind_address                = cu_cfg.f1ap_cfg.bind_addr;
  f1c_sctp_cfg.bind_port                   = F1AP_PORT;
  f1c_sctp_cfg.ppid                        = F1AP_PPID;
  f1c_cu_sctp_gateway_config f1c_server_cfg({f1c_sctp_cfg, *epoll_broker, *cu_cp_dlt_pcaps.f1ap});
  std::unique_ptr<srs_cu_cp::f1c_connection_server> cu_f1c_gw = srsran::create_f1c_gateway_server(f1c_server_cfg);

  // Create E1AP local connector
  std::unique_ptr<e1_local_connector> e1_gw =
      create_e1_local_connector(e1_local_sctp_connector_config{*cu_cp_dlt_pcaps.e1ap, *epoll_broker, 39412});

  // Create manager of timers for CU-CP and CU-UP, which will be
  // driven by the system timer slot ticks.
  timer_manager  app_timers{256};
  timer_manager* cu_timers = &app_timers;

  // Create time source that ticks the timers
  io_timer_source time_source{app_timers, *epoll_broker, std::chrono::milliseconds{1}};

  // Instantiate E2AP client gateway.
  std::unique_ptr<e2_connection_client> e2_gw_cu =
      create_cu_e2_client_gateway(cu_cfg.e2_cfg, *epoll_broker, *cu_cp_dlt_pcaps.e2ap);

  // Create CU-CP config.
  cu_cp_build_dependencies cu_cp_dependencies;
  cu_cp_dependencies.cu_cp_executor = workers.cu_cp_exec;
  cu_cp_dependencies.cu_cp_e2_exec  = workers.cu_cp_e2_exec;
  cu_cp_dependencies.timers         = cu_timers;
  cu_cp_dependencies.ngap_pcap      = cu_cp_dlt_pcaps.ngap.get();
  cu_cp_dependencies.broker         = epoll_broker.get();
  cu_cp_dependencies.e2_gw          = e2_gw_cu.get();
  // create CU-CP.
  auto              cu_cp_obj_and_cmds = cu_cp_app_unit->create_cu_cp(cu_cp_dependencies);
  srs_cu_cp::cu_cp& cu_cp_obj          = *cu_cp_obj_and_cmds.unit;

  // Create console helper object for commands and metrics printing.
  app_services::stdin_command_dispatcher command_parser(*epoll_broker, cu_cp_obj_and_cmds.commands);

  // Connect E1AP to CU-CP.
  e1_gw->attach_cu_cp(cu_cp_obj.get_e1_handler());

  // start CU-CP
  cu_cp_logger.info("Starting CU-CP...");
  cu_cp_obj.start();
  cu_cp_logger.info("CU-CP started successfully");

  // Check connection to AMF
  if (not cu_cp_obj.get_ng_handler().amfs_are_connected()) {
    report_error("CU-CP failed to connect to AMF");
  }

  // Connect F1-C to CU-CP and start listening for new F1-C connection requests.
  cu_f1c_gw->attach_cu_cp(cu_cp_obj.get_f1c_handler());

  {
    app_services::application_message_banners app_banner(app_name);

    while (is_app_running) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
  }

  // Stop CU-CP activity.
  cu_cp_obj.stop();

  // Close PCAPs
  cu_cp_logger.info("Closing PCAP files...");
  cu_cp_dlt_pcaps.close();
  // cu_up_dlt_pcaps.close();
  cu_cp_logger.info("PCAP files successfully closed.");

  // Stop workers
  cu_cp_logger.info("Stopping executors...");
  workers.stop();
  cu_cp_logger.info("Executors closed successfully.");

  srslog::flush();

  return 0;
}
