/*
 * Copyright (c) 2024 InMon Corp.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef __included_sflow_common_h__
#define __included_sflow_common_h__

#define SFLOW_USE_VAPI

/* main thread, and vapi thread */
typedef struct {
  u32 sw_if_index;
  u32 hw_if_index;
  u32 linux_if_index;
  u32 polled;
  int sflow_enabled;
} sflow_per_interface_data_t;

#endif /* __included_sflow_common_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

