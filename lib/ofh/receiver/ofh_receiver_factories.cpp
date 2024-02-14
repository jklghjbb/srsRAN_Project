/*
 *
 * Copyright 2021-2024 Software Radio Systems Limited
 *
 * By using this file, you agree to the terms and conditions set
 * forth in the LICENSE file which can be found at the top level of
 * the distribution.
 *
 */

#include "ofh_receiver_factories.h"
#include "ofh_data_flow_uplane_uplink_data_impl.h"
#include "ofh_data_flow_uplane_uplink_prach_impl.h"
#include "ofh_receiver_impl.h"
#include "ofh_sequence_id_checker_dummy_impl.h"
#include "ofh_sequence_id_checker_impl.h"
#include "srsran/ofh/compression/compression_factory.h"
#include "srsran/ofh/ecpri/ecpri_factories.h"
#include "srsran/ofh/ethernet/ethernet_factories.h"
#include "srsran/ofh/serdes/ofh_serdes_factories.h"

using namespace srsran;
using namespace ofh;

static std::unique_ptr<uplane_message_decoder> create_uplane_decoder(const receiver_config&       receiver_cfg,
                                                                     srslog::basic_logger&        logger,
                                                                     const ru_compression_params& compr_params)
{
  // Comrpessors.
  std::array<std::unique_ptr<ofh::iq_decompressor>, ofh::NOF_COMPRESSION_TYPES_SUPPORTED> decompr;
  for (unsigned i = 0; i != ofh::NOF_COMPRESSION_TYPES_SUPPORTED; ++i) {
    decompr[i] = create_iq_decompressor(static_cast<ofh::compression_type>(i), logger);
  }

  unsigned nof_prbs_ru =
      get_max_Nprb(bs_channel_bandwidth_to_MHz(receiver_cfg.ru_operating_bw), receiver_cfg.scs, frequency_range::FR1);

  // Open FrontHaul decoder.
  return (receiver_cfg.is_uplink_static_compr_hdr_enabled)
             ? ofh::create_static_compr_method_ofh_user_plane_packet_decoder(
                   logger,
                   receiver_cfg.scs,
                   receiver_cfg.cp,
                   nof_prbs_ru,
                   create_iq_decompressor_selector(std::move(decompr)),
                   compr_params)
             : ofh::create_dynamic_compr_method_ofh_user_plane_packet_decoder(
                   logger,
                   receiver_cfg.scs,
                   receiver_cfg.cp,
                   nof_prbs_ru,
                   create_iq_decompressor_selector(std::move(decompr)));
}

static std::unique_ptr<data_flow_uplane_uplink_prach>
create_uplink_prach_data_flow(const receiver_config&                            receiver_cfg,
                              srslog::basic_logger&                             logger,
                              std::shared_ptr<uplane_rx_symbol_notifier>        notifier,
                              std::shared_ptr<prach_context_repository>         prach_context_repo,
                              std::shared_ptr<uplink_cplane_context_repository> ul_cp_context_repo)
{
  data_flow_uplane_uplink_prach_impl_config config;
  config.is_prach_cplane_enabled = receiver_cfg.is_prach_control_plane_enabled;
  config.prach_eaxcs             = receiver_cfg.prach_eaxc;

  data_flow_uplane_uplink_prach_impl_dependencies dependencies;
  dependencies.logger                     = &logger;
  dependencies.notifier                   = notifier;
  dependencies.ul_cplane_context_repo_ptr = ul_cp_context_repo;
  dependencies.prach_context_repo         = prach_context_repo;
  dependencies.uplane_decoder = create_uplane_decoder(receiver_cfg, logger, receiver_cfg.prach_compression_params);

  return std::make_unique<data_flow_uplane_uplink_prach_impl>(config, std::move(dependencies));
}

static std::unique_ptr<data_flow_uplane_uplink_data>
create_uplink_data_flow(const receiver_config&                            receiver_cfg,
                        srslog::basic_logger&                             logger,
                        std::shared_ptr<uplane_rx_symbol_notifier>        notifier,
                        std::shared_ptr<uplink_context_repository>        ul_slot_context_repo,
                        std::shared_ptr<uplink_cplane_context_repository> ul_cp_context_repo)
{
  data_flow_uplane_uplink_data_impl_config config;
  config.ul_eaxc = receiver_cfg.ul_eaxc;

  data_flow_uplane_uplink_data_impl_dependencies dependencies;
  dependencies.logger                     = &logger;
  dependencies.notifier                   = notifier;
  dependencies.ul_cplane_context_repo_ptr = ul_cp_context_repo;
  dependencies.ul_context_repo            = ul_slot_context_repo;
  dependencies.uplane_decoder = create_uplane_decoder(receiver_cfg, logger, receiver_cfg.ul_compression_params);

  return std::make_unique<data_flow_uplane_uplink_data_impl>(config, std::move(dependencies));
}

static receiver_impl_dependencies
resolve_receiver_dependencies(const receiver_config&                            receiver_cfg,
                              srslog::basic_logger&                             logger,
                              std::unique_ptr<ether::receiver>                  eth_receiver,
                              std::shared_ptr<uplane_rx_symbol_notifier>        notifier,
                              std::shared_ptr<prach_context_repository>         prach_context_repo,
                              std::shared_ptr<uplink_context_repository>        ul_slot_context_repo,
                              std::shared_ptr<uplink_cplane_context_repository> ul_cp_context_repo)
{
  receiver_impl_dependencies dependencies;

  dependencies.logger = &logger;

  if (receiver_cfg.ignore_ecpri_payload_size_field) {
    dependencies.ecpri_decoder = ecpri::create_ecpri_packet_decoder_ignoring_payload_size(logger);
  } else {
    dependencies.ecpri_decoder = ecpri::create_ecpri_packet_decoder_using_payload_size(logger);
  }
  dependencies.eth_frame_decoder = ether::create_vlan_frame_decoder(logger);

  dependencies.data_flow_uplink =
      create_uplink_data_flow(receiver_cfg, logger, notifier, ul_slot_context_repo, ul_cp_context_repo);
  dependencies.data_flow_prach =
      create_uplink_prach_data_flow(receiver_cfg, logger, notifier, prach_context_repo, ul_cp_context_repo);

  dependencies.seq_id_checker =
      (receiver_cfg.ignore_ecpri_seq_id_field)
          ? static_cast<std::unique_ptr<sequence_id_checker>>(std::make_unique<sequence_id_checker_dummy_impl>())
          : static_cast<std::unique_ptr<sequence_id_checker>>(std::make_unique<sequence_id_checker_impl>());

  dependencies.eth_receiver = std::move(eth_receiver);

  return dependencies;
}

std::unique_ptr<receiver>
srsran::ofh::create_receiver(const receiver_config&                            receiver_cfg,
                             srslog::basic_logger&                             logger,
                             std::unique_ptr<ether::receiver>                  eth_rx,
                             std::shared_ptr<uplane_rx_symbol_notifier>        notifier,
                             std::shared_ptr<prach_context_repository>         prach_context_repo,
                             std::shared_ptr<uplink_context_repository>        ul_slot_context_repo,
                             std::shared_ptr<uplink_cplane_context_repository> ul_cp_context_repo)
{
  auto rx_depen = resolve_receiver_dependencies(
      receiver_cfg, logger, std::move(eth_rx), notifier, prach_context_repo, ul_slot_context_repo, ul_cp_context_repo);

  return std::make_unique<receiver_impl>(receiver_cfg, std::move(rx_depen));
}
