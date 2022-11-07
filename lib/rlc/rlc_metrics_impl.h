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

#include "srsgnb/rlc/rlc_metrics.h"
#include "srsgnb/srslog/srslog.h"
#include <mutex>

namespace srsgnb {

class rlc_tx_metrics : rlc_tx_metrics_interface
{
  rlc_bearer_tx_metrics_container metrics = {};
  std::mutex                      metrics_mutex;

public:
  void metrics_set_mode(rlc_mode mode) { metrics.mode = mode; }

  void metrics_add_sdus(uint32_t num_sdus_, size_t num_sdu_bytes_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_sdus += num_sdus_;
    metrics.num_sdu_bytes += num_sdu_bytes_;
  }

  void metrics_add_lost_sdus(uint32_t num_sdus_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_dropped_sdus += num_sdus_;
  }

  void metrics_add_pdus(uint32_t num_pdus_, size_t num_pdu_bytes_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_pdus += num_pdus_;
    metrics.num_pdu_bytes += num_pdu_bytes_;
  }

  // TM specific metrics
  void metrics_add_small_alloc(uint32_t num_allocs_)
  {
    srsgnb_assert(metrics.mode == rlc_mode::tm, "Wrong mode for TM specific metrics");
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.mode_specific.tm.num_small_allocs += num_allocs_;
  }

  // UM specific metrics
  void metrics_add_sement(uint32_t num_segments_)
  {
    srsgnb_assert(metrics.mode == rlc_mode::um_bidir, "Wrong mode for UM specific metrics");
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.mode_specific.um.num_sdu_segments += num_segments_;
  }

  // AM specific metrics
  void metrics_add_retx_pdus(uint32_t num_retx_)
  {
    srsgnb_assert(metrics.mode == rlc_mode::am, "Wrong mode for UM specific metrics");
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.mode_specific.am.num_retx_pdus += num_retx_;
  }

  // Metrics getters and setters
  rlc_bearer_tx_metrics_container get_metrics() final
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    return metrics;
  }

  rlc_bearer_tx_metrics_container get_and_reset_metrics() final
  {
    std::lock_guard<std::mutex>     lock(metrics_mutex);
    rlc_bearer_tx_metrics_container ret = metrics;
    metrics                             = {};
    return ret;
  }

  void reset_metrics() final
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics = {};
  }
};

class rlc_rx_metrics : rlc_rx_metrics_interface
{
  rlc_bearer_rx_metrics_container metrics = {};
  std::mutex                      metrics_mutex;

public:
  void set_mode(rlc_mode mode) { metrics.mode = mode; }

  void metrics_add_sdus(uint32_t num_sdus_, size_t num_sdu_bytes_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_sdus += num_sdus_;
    metrics.num_sdu_bytes += num_sdu_bytes_;
  }

  void metrics_add_pdus(uint32_t num_pdus_, size_t num_pdu_bytes_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_pdus += num_pdus_;
    metrics.num_pdu_bytes += num_pdu_bytes_;
  }

  void metrics_add_lost_pdus(uint32_t num_pdus_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_lost_pdus += num_pdus_;
  }

  void metrics_add_malformed_pdus(uint32_t num_pdus_)
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics.num_malformed_pdus += num_pdus_;
  }

  rlc_bearer_rx_metrics_container get_metrics() final
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    return metrics;
  }

  rlc_bearer_rx_metrics_container get_and_reset_metrics() final
  {
    std::lock_guard<std::mutex>     lock(metrics_mutex);
    rlc_bearer_rx_metrics_container ret = metrics;
    metrics                             = {};
    return ret;
  }

  void reset_metrics() final
  {
    std::lock_guard<std::mutex> lock(metrics_mutex);
    metrics = {};
  }
};

} // namespace srsgnb
