#
# Copyright 2021-2024 Software Radio Systems Limited
#
# This file is part of srsRAN
#
# srsRAN is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of
# the License, or (at your option) any later version.
#
# srsRAN is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# A copy of the GNU Affero General Public License can be found in
# the LICENSE file in the top-level directory of this distribution
# and at http://www.gnu.org/licenses/.
#

set(SOURCES
        cu_up_executor_mapper.cpp
      cu_up_factory.cpp
      cu_up_impl.cpp
      cu_up_manager_impl.cpp
      ue_manager.cpp
      pdu_session_manager_impl.cpp
      routines/initial_cu_up_setup_routine.cpp
)

add_library(srsran_cu_up STATIC ${SOURCES})

target_link_libraries(srsran_cu_up
        srsran_e1ap_common
        srsran_e1ap_cu_up
        srsran_gtpu
        srsran_pdcp
        srsran_f1u_cu_up
        srsran_gateway
        e1ap_asn1
        srsran_sdap
        srsran_security
        srsran_support
        srslog
        bpf
        ${CMAKE_SOURCE_DIR}/xdp-tools/lib/libxdp/libxdp.so)

add_custom_target(cu_up_xdp.o ALL
                  DEPENDS ${CMAKE_SOURCE_DIR}/build/apps/cu_up/xdp_cu_up.o)

add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/build/apps/cu_up/xdp_cu_up.o
                   DEPENDS ${CMAKE_SOURCE_DIR}/build/apps/cu_up/xdp_cu_up.ll
                   COMMAND llc -march=bpf -filetype=obj -o ${CMAKE_SOURCE_DIR}/build/apps/cu_up/xdp_cu_up.o ${CMAKE_SOURCE_DIR}/build/apps/cu_up/xdp_cu_up.ll)

add_custom_command(OUTPUT ${CMAKE_SOURCE_DIR}/build/lib/cu_up/xdp_cu_up.ll
                  DEPENDS ${CMAKE_SOURCE_DIR}/lib/cu_up/xdp/xdp_cu_up.c
                  COMMAND clang -S 
                          -target bpf
                          -D __BPF_TRACING__
                          -Wall
                          -Wno-unused-value
                          -Wno-pointer-sign
                          -Wno-compare-distinct-pointer-types
                          -Werror 
                          -O2
                          -emit-llvm
                          -c
                          -g
                          -o ${CMAKE_SOURCE_DIR}/build/apps/cu_up/xdp_cu_up.ll
                          ${CMAKE_SOURCE_DIR}/lib/cu_up/xdp/xdp_cu_up.c)

add_dependencies(srsran_cu_up cu_up_xdp.o)
