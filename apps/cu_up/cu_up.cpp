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

// common
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

#include "apps/services/application_message_banners.h"
#include "apps/services/application_tracer.h"
#include "apps/services/buffer_pool/buffer_pool_manager.h"
#include "apps/services/stdin_command_dispatcher.h"
#include "apps/services/worker_manager.h"
#include "apps/services/worker_manager_config.h"

// cu-up app config
#include "apps/cu_up/cu_up_appconfig_cli11_schema.h"
#include "cu_up_appconfig.h"
#include "cu_up_appconfig_validator.h"
#include "cu_up_appconfig_yaml_writer.h"

// app unit config
#include "apps/units/cu_up/cu_up_application_unit.h"
#include "apps/units/cu_up/cu_up_unit_config.h"
#include "apps/units/cu_up/pcap_factory.h"
#include "srsran/cu_up/cu_up.h"

#include "apps/gnb/gnb_appconfig_translators.h"


// interface and gateway
#include "srsran/e1ap/gateways/e1_network_client_factory.h"
#include "srsran/f1u/cu_up/split_connector/f1u_split_connector_factory.h"
#include "srsran/gateways/udp_network_gateway.h"
#include "srsran/gtpu/gtpu_config.h"
#include "srsran/gtpu/gtpu_demux_factory.h"
#include "srsran/gtpu/ngu_gateway.h"
// #include "srsran/pcap/dlt_pcap.h"


#include <atomic>
#include <thread>

using namespace srsran;

/// \file
/// \brief Application of a Central Unit User Plane (CU-UP) with combined CU control-plane (CU-CP) and CU user-plane (CU-UP).

static std::string config_file;

/// Flag that indicates if the application is running or being shutdown.
static std::atomic<bool> is_app_running = {true};
/// Maximum number of configuration files allowed to be concatenated in the command line.
static constexpr unsigned MAX_CONFIG_FILES = 10;

static void populate_cli11_generic_args(CLI::App& app)
{
  fmt::memory_buffer buffer;
  format_to(buffer, "srsRAN 5G CU-UP version {} ({})", get_version(), get_build_hash());
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
                              cu_up_application_unit& cu_up_app_unit)
{
  // Set log-level of app and all non-layer specific components to app level.
  for (const auto& id : {"ALL", "SCTP-GW", "IO-EPOLL", "UDP-GW", "PCAP"}) {
    auto& logger = srslog::fetch_basic_logger(id, false);
    logger.set_level(log_cfg.lib_level);
    logger.set_hex_dump_max_size(log_cfg.hex_max_size);
  }

  auto& app_logger = srslog::fetch_basic_logger("CU-UP", false);
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
  cu_up_app_unit.on_loggers_registration();
}

static void fill_cu_worker_manager_config(worker_manager_config& config, const srs_cu::cu_up_appconfig& unit_cfg)
{
  config.nof_low_prio_threads  = unit_cfg.expert_execution_cfg.threads.non_rt_threads.nof_non_rt_threads;
  config.low_prio_sched_config = unit_cfg.expert_execution_cfg.affinities.low_priority_cpu_cfg;
}

int main(int argc, char** argv)
{
  // Set the application error handler.
  set_error_handler(app_error_report_handler);

  static constexpr std::string_view app_name = "CU-UP";
  app_services::application_message_banners::announce_app_and_version(app_name);

  // Set interrupt and cleanup signal handlers.
  register_interrupt_signal_handler(interrupt_signal_handler);
  register_cleanup_signal_handler(cleanup_signal_handler);

  // Enable backtrace.
  enable_backtrace();

  // Setup and configure config parsing.
  CLI::App app("srsCU-UP application");
  app.config_formatter(create_yaml_config_parser());
  app.allow_config_extras(CLI::config_extras_mode::error);
  // Fill the generic application arguments to parse.
  populate_cli11_generic_args(app);

  // Configure CLI11 with the CU application configuration schema.
  srs_cu::cu_up_appconfig cu_up_cfg;
  configure_cli11_with_cu_appconfig_schema(app, cu_up_cfg);

  auto cu_up_app_unit = create_cu_up_application_unit("cu-up");
  cu_up_app_unit->on_parsing_configuration_registration(app);

  // Parse arguments.
  CLI11_PARSE(app, argc, argv);

  // Check the modified configuration.
  if (!validate_cu_appconfig(cu_up_cfg) ||
      !cu_up_app_unit->on_configuration_validation(os_sched_affinity_bitmask::available_cpus())) {
    report_error("Invalid configuration detected.\n");
  }

  // Set up logging.
  initialize_log(cu_up_cfg.log_cfg.filename);
  register_app_logs(cu_up_cfg.log_cfg, *cu_up_app_unit);

  // Log input configuration.
  srslog::basic_logger& config_logger = srslog::fetch_basic_logger("CONFIG");
  if (config_logger.debug.enabled()) {
    YAML::Node node;
    fill_cu_appconfig_in_yaml_schema(node, cu_up_cfg);
    cu_up_app_unit->dump_config(node);
    config_logger.debug("Input configuration (all values): \n{}", YAML::Dump(node));
  } else {
    config_logger.info("Input configuration (only non-default values): \n{}", app.config_to_str(false, false));
  }

  srslog::basic_logger&            cu_up_logger = srslog::fetch_basic_logger("CU");
  app_services::application_tracer app_tracer;
  if (not cu_up_cfg.log_cfg.tracing_filename.empty()) {
    app_tracer.enable_tracer(cu_up_cfg.log_cfg.tracing_filename, cu_up_logger);
  }

  // Setup size of byte buffer pool.
  app_services::buffer_pool_manager buffer_pool_service(cu_up_cfg.buffer_pool_config);

  // Check and log included CPU features and check support by current CPU
  if (cpu_supports_included_features()) {
    cu_up_logger.debug("Required CPU features: {}", get_cpu_feature_info());
  } else {
    // Quit here until we complete selection of the best matching implementation for the current CPU at runtime.
    cu_up_logger.error("The CPU does not support the required CPU features that were configured during compile time: {}",
                    get_cpu_feature_info());
    report_error("The CPU does not support the required CPU features that were configured during compile time: {}\n",
                 get_cpu_feature_info());
  }

  // Check some common causes of performance issues and print a warning if required.
  check_cpu_governor(cu_up_logger);
  check_drm_kms_polling(cu_up_logger);

  // Create worker manager.
  worker_manager_config worker_manager_cfg;
  fill_cu_worker_manager_config(worker_manager_cfg, cu_up_cfg);
  cu_up_app_unit->fill_worker_manager_config(worker_manager_cfg);
  worker_manager workers{worker_manager_cfg};

  cu_up_dlt_pcaps cu_up_dlt_pcaps =
      create_cu_up_dlt_pcaps(cu_up_app_unit->get_cu_up_unit_config().pcap_cfg, *workers.get_executor_getter());

  // Create IO broker.
  const auto&                low_prio_cpu_mask = cu_up_cfg.expert_execution_cfg.affinities.low_priority_cpu_cfg.mask;
  io_broker_config           io_broker_cfg(low_prio_cpu_mask);
  std::unique_ptr<io_broker> epoll_broker = create_io_broker(io_broker_type::epoll, io_broker_cfg);

  // Create F1-U GW (TODO factory and cleanup).
  gtpu_demux_creation_request cu_f1u_gtpu_msg   = {};
  cu_f1u_gtpu_msg.cfg.warn_on_drop              = true;
  cu_f1u_gtpu_msg.gtpu_pcap                     = cu_up_dlt_pcaps.f1u.get();
  std::unique_ptr<gtpu_demux> cu_f1u_gtpu_demux = create_gtpu_demux(cu_f1u_gtpu_msg);
  udp_network_gateway_config  cu_f1u_gw_config  = {};
  cu_f1u_gw_config.bind_address                 = cu_up_cfg.nru_cfg.bind_addr;
  cu_f1u_gw_config.bind_port                    = GTPU_PORT;
  cu_f1u_gw_config.reuse_addr                   = false;
  cu_f1u_gw_config.pool_occupancy_threshold     = cu_up_cfg.nru_cfg.pool_occupancy_threshold;
  std::unique_ptr<srs_cu_up::ngu_gateway> cu_f1u_gw =
      srs_cu_up::create_udp_ngu_gateway(cu_f1u_gw_config, *epoll_broker, workers.cu_up_exec_mapper->io_ul_executor());
  std::unique_ptr<f1u_cu_up_udp_gateway> cu_f1u_conn =
      srs_cu_up::create_split_f1u_gw({*cu_f1u_gw, *cu_f1u_gtpu_demux, *cu_up_dlt_pcaps.f1u, GTPU_PORT});

  // create E1AP client
  sctp_network_connector_config sctp_client;
  sctp_client.if_name         = "E1";
  sctp_client.dest_name       = "CU-CP";
  sctp_client.connect_address = cu_up_cfg.e1_client_cfg.addr;
  sctp_client.connect_port    = cu_up_cfg.e1_client_cfg.port;
  sctp_client.ppid            = E1AP_PPID;
  std::unique_ptr<dlt_pcap> null_pcap_writer = create_null_dlt_pcap();
  // Note: We only need to save the PCAPs in one side of the connection.
  std::unique_ptr<srs_cu_up::e1_connection_client> e1_client = 
      create_e1_gateway_client(e1_cu_up_sctp_gateway_config{sctp_client, *epoll_broker, *null_pcap_writer});


  // Create manager of timers for CU-CP and CU-UP, which will be
  // driven by the system timer slot ticks.
  timer_manager  app_timers{256};
  timer_manager* cu_timers = &app_timers;

  // Create time source that ticks the timers
  io_timer_source time_source{app_timers, *epoll_broker, std::chrono::milliseconds{1}};

  // Create and start CU-UP
  cu_up_unit_dependencies cu_up_unit_deps;
  cu_up_unit_deps.workers          = &workers;
  cu_up_unit_deps.e1ap_conn_client = e1_client.get();
  cu_up_unit_deps.f1u_gateway      = cu_f1u_conn.get();
  cu_up_unit_deps.gtpu_pcap        = cu_up_dlt_pcaps.n3.get();
  cu_up_unit_deps.timers           = cu_timers;
  cu_up_unit_deps.io_brk           = epoll_broker.get();

  std::unique_ptr<srs_cu_up::cu_up_interface> cu_up_obj = cu_up_app_unit->create_cu_up_unit(cu_up_unit_deps);
  cu_up_obj->start();

  {
    app_services::application_message_banners app_banner(app_name);

    while (is_app_running) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
    }
  }

  // Stop CU-UP activity.
  cu_up_obj->stop();

  // Close PCAPs
  cu_up_logger.info("Closing PCAP files...");
  cu_up_dlt_pcaps.close();
  cu_up_logger.info("PCAP files successfully closed.");

  // Stop workers
  cu_up_logger.info("Stopping executors...");
  workers.stop();
  cu_up_logger.info("Executors closed successfully.");

  srslog::flush();

  return 0;
}
