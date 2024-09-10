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
static void *spt_process_samples(void *ctx) {
  sflow_main_t *smp = (sflow_main_t *)ctx;
  vlib_set_thread_name("sflow");
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000 };
  while(smp->running) {
    nanosleep(&ts, NULL);
    for(u32 thread_index = 0; thread_index < smp->total_threads; thread_index++) {
      sflow_per_thread_data_t *sfwk = vec_elt_at_index(smp->per_thread_data, thread_index);
      // TODO: dequeue and write multiple samples at a time
      sflow_sample_t sample;
      if(svm_fifo_dequeue(sfwk->fifo, sizeof(sflow_sample_t), (u8 *)&sample) == sizeof(sflow_sample_t)) {
	SFLOWPSSpec spec = {};
	u32 ps_group = 1; /* group==1 => ingress. Use group==2 for egress. */
	u16 header_protocol = 1; /* ethernet */
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_SAMPLE_GROUP, ps_group);
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_IIFINDEX, sample.input_if_index);
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_OIFINDEX, sample.output_if_index);
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_ORIGSIZE, sample.sampled_packet_size);
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_GROUP_SEQ, sample.thread_seqN);
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_SAMPLE_RATE, sample.samplingN);
	SFLOWPSSpec_setAttr(&spec, SFLOWPS_PSAMPLE_ATTR_DATA, sample.header, sample.header_bytes);
	SFLOWPSSpec_setAttrInt(&spec, SFLOWPS_PSAMPLE_ATTR_PROTO, header_protocol);
	SFLOWPSSpec_send(&smp->sflow_psample, &spec);
      }
    }
  }
  return NULL;
}

void sflow_start(sflow_main_t *smp) {
  clib_warning("sflow_start");
  smp->running = 1;
  
  /* set up (or reset) sampling context for each thread */
  vlib_thread_main_t *tm = &vlib_thread_main;
  smp->total_threads = 1 + tm->n_threads;
  vec_validate (smp->per_thread_data, smp->total_threads);
  for(u32 thread_index = 0; thread_index < smp->total_threads; thread_index++) {
    sflow_per_thread_data_t *sfwk = vec_elt_at_index(smp->per_thread_data, thread_index);
    if(sfwk->smpN != smp->samplingN) {
      sfwk->smpN = smp->samplingN;
      sfwk->seed = thread_index;
      sfwk->skip = sflow_next_random_skip(sfwk);
      if(sfwk->fifo == NULL) {
	fifo_segment_create_args_t _a, *a = &_a;
	clib_memset (a, 0, sizeof (*a));
	// TODO: do we need separate name for each worker FIFO?
	a->segment_name = "fifo-sflow-worker";
	a->segment_size = SFLOW_FIFO_SIZE;
	a->segment_type = SSVM_SEGMENT_PRIVATE;
	// TODO: test return codes and print errors
	fifo_segment_create(&sfwk->fsm, a);
	sfwk->fs = fifo_segment_get_segment(&sfwk->fsm, a->new_segment_indices[0]);
	// TODO: try to understand what these parameters mean
	sfwk->fifo = fifo_segment_alloc_fifo_w_slice(sfwk->fs, 0, SFLOW_FIFO_SLICE, FIFO_SEGMENT_TX_FIFO);
      }
      
      clib_warning("sflow startup: samplingN=%u thread=%u skip=%u",
		   smp->samplingN,
		   thread_index,
		   sfwk->skip);
    }
  }
  
  /* Some per-thread numbers are maintained only in the main thread. */
  vec_validate (smp->main_per_thread_data, smp->total_threads);

  /* open PSAMPLE netlink channel for writing */
  SFLOWPS_open(&smp->sflow_psample);

  /* fork sample-processing thread */
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, VLIB_THREAD_STACK_SIZE);
  pthread_create(&smp->spthread, &attr, spt_process_samples, smp);
}

void sflow_stop(sflow_main_t *smp) {
  clib_warning("sflow_stop");
  /* TODO: Setting smp->running to 0 should trigger clean exit from spthread
     so we can pthread_join() - but if it is blocked then this will
     never return so perhaps we should pthread_cancel() it instead? */
  smp->running = 0;
  SFLOWPS_close(&smp->sflow_psample);
  //pthread_cancel(smp->spthread, NULL);
  pthread_join(smp->spthread, NULL);
  clib_warning("sflow_stop_done");
}

void sflow_sampling_start_stop(sflow_main_t *smp) {
  int run = (smp->samplingN != 0
	     && smp->interfacesEnabled != 0);
  if(run != smp->running) {
    if(run)
      sflow_start(smp);
    else
      sflow_stop(smp);
  }
}

int sflow_sampling_rate (sflow_main_t * smp, u32 samplingN)
{
  smp->samplingN = samplingN;
  sflow_sampling_start_stop(smp);
  return 0;
}

int sflow_enable_disable (sflow_main_t * smp, u32 sw_if_index, int enable_disable)
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

  /* keep a count so we know when to turn on or off */
  smp->interfacesEnabled += (enable_disable) ? 1 : -1;

  /* insert in graph */
  /* TODO: do we need to do this for every interface? */
  /* TODO: what happens if we enable, disable and then enable again */
  vnet_feature_enable_disable ("device-input", "sflow",
                               sw_if_index, enable_disable, 0, 0);

  sflow_sampling_start_stop(smp);
  return 0;
}

static clib_error_t *
sflow_sampling_rate_command_fn (vlib_main_t * vm,
				unformat_input_t * input,
				vlib_cli_command_t * cmd)
{
  sflow_main_t * smp = &sflow_main;
  u32 sampling_N = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &sampling_N))
	;
      else
        break;
    }
  
  if (sampling_N == ~0)
    return clib_error_return (0, "Please specify a sampling rate...");

  rv = sflow_sampling_rate (smp, sampling_N);

  switch(rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_enable_disable returned %d",
				rv);
    }
  return 0;
}

static clib_error_t *
sflow_enable_disable_command_fn (vlib_main_t * vm,
				 unformat_input_t * input,
				 vlib_cli_command_t * cmd)
{
  sflow_main_t * smp = &sflow_main;
  u32 sw_if_index = ~0;
  int enable_disable = 1;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "disable"))
        enable_disable = 0;
      else if (unformat (input, "%U", unformat_vnet_sw_interface,
                         smp->vnet_main, &sw_if_index))
        ;
      else
        break;
    }

  if (sw_if_index == ~0)
    return clib_error_return (0, "Please specify an interface...");

  rv = sflow_enable_disable (smp, sw_if_index, enable_disable);

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
    .short_help = "sflow enable-disable <interface-name> [disable]",
    .function = sflow_enable_disable_command_fn,
  };

VLIB_CLI_COMMAND (sflow_sampling_rate_command, static) =
  {
    .path = "sflow sampling-rate",
    .short_help = "sflow sampling-rate <N>",
    .function = sflow_sampling_rate_command_fn,
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
			      (int) (mp->enable_disable));

  REPLY_MACRO(VL_API_SFLOW_ENABLE_DISABLE_REPLY);
}

static void vl_api_sflow_sampling_rate_t_handler
(vl_api_sflow_sampling_rate_t * mp)
{
  vl_api_sflow_sampling_rate_reply_t * rmp;
  sflow_main_t * smp = &sflow_main;
  int rv;
  
  rv = sflow_sampling_rate (smp,
			    ntohl(mp->sampling_N));
  
  REPLY_MACRO(VL_API_SFLOW_SAMPLING_RATE_REPLY);
}

/* API definitions */
#include <sflow/sflow.api.c>

static clib_error_t * sflow_init (vlib_main_t * vm)
{
  sflow_main_t * smp = &sflow_main;
  clib_error_t * error = 0;

  smp->vlib_main = vm;
  smp->vnet_main = vnet_get_main();

  /* set default sampling-rate so that "enable" is all that is necessary */
  smp->samplingN = SFLOW_DEFAULT_SAMPLING_N;
  /* TODO: make this a CLI parameter too */
  smp->header_bytes = SFLOW_DEFAULT_HEADER_BYTES;

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
