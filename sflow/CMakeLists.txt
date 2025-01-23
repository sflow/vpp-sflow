
# Copyright (c) 2024 InMon Corp.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

include_directories(${CMAKE_SOURCE_DIR}/vpp-api ${CMAKE_CURRENT_BINARY_DIR}/../../vpp-api)

# The preprocessor flag SFLOW_USE_VAPI controls whether the sflow plugin will
# attempt to contact the linux-cp plugin using the binary VAPI. It has to be a
# preprocessor flag so it can suppress the "#include" statements that define
# that linux-cp api, because those include files will be missing if linux-cp
# is excluded from the build.
# Note that it is OK for the linux-cp plugin to be compiled but not loaded. In
# that scenario the VAPI calls will be compiled but will fail gracefully at runtime.

# This "excluded_plugins" list in constructed in vpp/src/plugins/CMakeLists.txt.

LIST(FIND excluded_plugins linux-cp exc_index)
if(${exc_index} EQUAL "-1")
  message(WARNING "sflow plugin - linux-cp plugin included: compiling VAPI calls")
  add_compile_definitions(SFLOW_USE_VAPI)
else()
  message(WARNING "sflow plugin - linux-cp plugin excluded: not compiling VAPI calls")
endif()

# Could have used this more direct test for the include file, but this makes the
# assumption that cmake has already processed the linux-cp plugin.

# if(EXISTS "${CMAKE_CURRENT_BINARY_DIR}/../../vpp-api/vapi/lcp.api.vapi.h")
#  message(WARNING "sFlow plugin - linux-cp plugin api found: compiling VAPI calls")
#  add_compile_definitions(SFLOW_USE_VAPI)
# endif()

add_vpp_plugin(sflow
  SOURCES
  sflow.c
  node.c
  sflow_common.h
  sflow.h
  sflow_psample.c
  sflow_psample.h
  sflow_psample_fields.h
  sflow_usersock.c
  sflow_usersock.h
  sflow_vapi.c
  sflow_vapi.h

  MULTIARCH_SOURCES
  node.c

  API_FILES
  sflow.api

  API_TEST_SOURCES
  sflow_test.c

  LINK_LIBRARIES
  vppapiclient
  vapiclient
)
