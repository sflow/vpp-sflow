/*
 * sflow.c - skeleton vpp engine plug-in
 *
 * Copyright (c) <current-year> <your-organization>
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

#include <vnet/vnet.h>
#include <vnet/plugin/plugin.h>
#include <sflow/sflow.h>

#include <vlibapi/api.h>
#include <vlibmemory/api.h>
#include <vpp/app/version.h>
#include <stdbool.h>

#include <sflow/sflow.api_enum.h>
#include <sflow/sflow.api_types.h>
#include <sflow/sflow_psample.h>

#define REPLY_MSG_ID_BASE smp->msg_id_base
#include <vlibapi/api_helper_macros.h>

sflow_main_t sflow_main;

/* Action function shared between message handler and debug CLI */

int sflow_enable_disable (sflow_main_t * smp, u32 sw_if_index, u32 sampling_N,
			   int enable_disable)
{
  vnet_sw_interface_t * sw;
  
  /* Utterly wrong? */
  if (pool_is_free_index (smp->vnet_main->interface_main.sw_interfaces,
                          sw_if_index))
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  /* Not a physical port? */
  sw = vnet_get_sw_interface (smp->vnet_main, sw_if_index);
  if (sw->type != VNET_SW_INTERFACE_TYPE_HARDWARE)
    return VNET_API_ERROR_INVALID_SW_IF_INDEX;
  
  vnet_feature_enable_disable ("device-input", "sflow",
                               sw_if_index, enable_disable, 0, 0);

  /* main config */
  smp->samplingN = sampling_N;
  smp->header_bytes = SFLOW_DEFAULT_HEADER_BYTES;

  /* set up sampling context for each thread */
  vlib_thread_main_t *tm = &vlib_thread_main;
  smp->total_threads = 1 + tm->n_threads;
  vec_validate (smp->per_thread_data, smp->total_threads);
  for(u32 thread_index = 0; thread_index < smp->total_threads; thread_index++) {
    sflow_per_thread_data_t *sfwk = vec_elt_at_index(smp->per_thread_data, thread_index);
    if(sfwk->smpN != smp->samplingN) {
      sfwk->smpN = smp->samplingN;
      sfwk->seed = thread_index;
      sfwk->skip = sflow_next_random_skip(sfwk);
      clib_warning("sflow startup 20240908: samplingN=%u thread=%u skip=%u",
		   smp->samplingN,
		   thread_index,
		   sfwk->skip);
    }
  }

  /* Some per-thread numbers are maintained only in the main thread. */
  vec_validate (smp->main_per_thread_data, smp->total_threads);

  /* open PSAMPLE netlink channel for writing */
  SFLOWPS_open(&smp->sflow_psample);
  
  return 0;
}

static clib_error_t *
sflow_enable_disable_command_fn (vlib_main_t * vm,
				  unformat_input_t * input,
				  vlib_cli_command_t * cmd)
{
  sflow_main_t * smp = &sflow_main;
  u32 sw_if_index = ~0;
  u32 sampling_N = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         smp->vnet_main, &sw_if_index))
        ;

      else if (unformat (input, "%u", &sampling_N))
	;
      else
        break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  if (sampling_N == ~0)
    return clib_error_return (0, "Please specify a sampling rate...");

  rv = sflow_enable_disable (smp, sw_if_index, sampling_N, enable_disable);

  switch(rv)
    {
    case 0:
      break;

    case VNET_API_ERROR_INVALID_SW_IF_INDEX:
      return clib_error_return
	(0, "Invalid interface, only works on physical ports");
      break;

    case VNET_API_ERROR_UNIMPLEMENTED:
      return clib_error_return (0, "Device driver doesn't support redirection");
      break;

    default:
      return clib_error_return (0, "sflow_enable_disable returned %d",
				rv);
    }
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND (sflow_enable_disable_command, static) =
  {
    .path = "sflow enable-disable",
    .short_help =
    "sflow enable-disable <interface-name> <sampling_N> [disable]",
    .function = sflow_enable_disable_command_fn,
  };
/* *INDENT-ON* */

/* API message handler */
static void vl_api_sflow_enable_disable_t_handler
(vl_api_sflow_enable_disable_t * mp)
{
  vl_api_sflow_enable_disable_reply_t * rmp;
  sflow_main_t * smp = &sflow_main;
  int rv;

  rv = sflow_enable_disable (smp,
			      ntohl(mp->sw_if_index),
			      ntohl(mp->sampling_N),
			      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_SFLOW_ENABLE_DISABLE_REPLY);
}

/* API definitions */
#include <sflow/sflow.api.c>

static clib_error_t * sflow_init (vlib_main_t * vm)
{
  sflow_main_t * smp = &sflow_main;
  clib_error_t * error = 0;

  smp->vlib_main = vm;
  smp->vnet_main = vnet_get_main();

  /* Add our API messages to the global name_crc hash table */
  smp->msg_id_base = setup_message_id_table ();
  return error;
}

VLIB_INIT_FUNCTION (sflow_init);

/* *INDENT-OFF* */
VNET_FEATURE_INIT (sflow, static) =
  {
    .arc_name = "device-input",
    .node_name = "sflow",
    .runs_before = VNET_FEATURES ("ethernet-input"),
  };
/* *INDENT-ON */

/* *INDENT-OFF* */
VLIB_PLUGIN_REGISTER () =
  {
    .version = VPP_BUILD_VER,
    .description = "sFlow random packet sampling",
  };
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */
