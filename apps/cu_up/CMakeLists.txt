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

add_executable(srscu_up
    cu_up.cpp
	cu_up_appconfig_cli11_schema.cpp
	cu_up_appconfig_validator.cpp
	cu_up_appconfig_yaml_writer.cpp
    ../gnb/gnb_appconfig_translators.cpp
)

install(TARGETS srscu_up
        RUNTIME)

target_link_libraries(srscu_up
        srsran_app_services
        srsran_support
        srsran_versioning
        srsran_cu_up_app_unit
        srsran_e1_gateway
        srsgnb_app_f1u_cu_up_split_connector
        srsran_pcap
        )

add_backward(srscu_up)

target_include_directories(srscu_up PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/external)

