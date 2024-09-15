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

#include <vpp-api/client/stat_client.h>
#include <vlib/stats/stats.h>

#define REPLY_MSG_ID_BASE smp->msg_id_base
#include <vlibapi/api_helper_macros.h>

sflow_main_t sflow_main;

static void
sflow_stat_segment_client_init (void)
{
  stat_client_main_t *scm = &stat_client_main;
  vlib_stats_segment_t *sm = vlib_stats_get_segment ();
  uword size;

  size = sm->memory_size ? sm->memory_size : STAT_SEGMENT_DEFAULT_SIZE;
  scm->memory_size = size;
  scm->shared_header = sm->shared_header;
  scm->directory_vector =
    stat_segment_adjust (scm, (void *) scm->shared_header->directory_vector);
}

static void
update_counter_vector_combined(sflow_main_t *smp, stat_segment_data_t *res, SFL_if_counters_t *ifCtrs, u32 hw_if_index) {
  u8 *name = (u8 *)res->name;
  for (int th = 0; th < vec_len (res->simple_counter_vec); th++) {
    for (int intf = 0; intf < vec_len (res->combined_counter_vec[intf]); intf++) {
      if(intf != hw_if_index)
	continue;
      u64 pkts = res->combined_counter_vec[th][intf].packets;
      u64 byts = res->combined_counter_vec[th][intf].bytes;
      if(pkts || byts) {
	clib_warning("%s_packets{thread=\"%d\",interface=\"%d\"} %lld\n",
		     name, th, intf, pkts);
	clib_warning("%s_bytes{thread=\"%d\",interface=\"%d\"} %lld\n",
		     name, th, intf, byts);
	// TODO: do we really have to look at the name string to know what it is?
	if(strstr((char *)name, "/tx_")) {
	  ifCtrs->ifOutUcastPkts += pkts;
	  ifCtrs->ifOutOctets += byts;
	}
	if(strstr((char *)name, "/rx_")) {
	  ifCtrs->ifInUcastPkts += pkts;
	  ifCtrs->ifInOctets += byts;
	}
      }
    }
  }
}

static void update_counters(sflow_main_t *smp, sflow_main_per_interface_data_t *sfif) {
  vnet_hw_interface_t *hw = vnet_get_hw_interface(smp->vnet_main, sfif->hw_if_index);
  // TODO: what is expected in patterns? This doesn't work:
  u8 *patterns[] = { NULL, NULL };
  patterns[0] = (u8 *)"interfaces";
  // This gives us a list of stat integers
  u32 *stats = stat_segment_ls(NULL);
  stat_segment_data_t *res = NULL;
  // And we can grab a vector of stat_segment_data_t objects
 retry:
  res = stat_segment_dump (stats);
  if (res == NULL) {
    /* Memory layout has changed */
    if (stats)
      vec_free (stats);
    stats = stat_segment_ls (NULL);
    goto retry;
  }

  u64 speed = hw->link_speed;
  speed = (speed == ~0) ? 0 : (speed * 1000); // TODO or 1024?

  SFL_if_counters_t ifCtrs = {
    .ifIndex = sfif->hw_if_index,
    .ifType = 6, // ethernetcsmacd
    .ifSpeed = speed,
    .ifStatus = SFLSTATUS_ADMIN_UP | SFLSTATUS_OPER_UP,
    .ifDirection = 1, // full-duplex
  };
  // and accumulate the (per-thread) entries for this interface
  for (int ii = 0; ii < vec_len (res); ii++) {
    switch (res[ii].type) {
    case STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE:
      // s = dump_counter_vector_simple (&res[ii], s, used_only);
      //clib_warning("stat simple: %s\n", res[ii].name);
      break;
    case STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED:
      // clib_warning("stat combined: %s\n", res[ii].name);
      update_counter_vector_combined (smp, &res[ii], &ifCtrs, sfif->hw_if_index);
      break;
    case STAT_DIR_TYPE_SCALAR_INDEX:
      //clib_warning("stat scalar: %s\n", res[ii].name);
      //s = dump_scalar_index (&res[ii], s, used_only);
      break;
    case STAT_DIR_TYPE_NAME_VECTOR:
      //clib_warning("stat name_vector: %s\n", res[ii].name);
      //s = dump_name_vector (&res[ii], s, used_only);
      break;
    case STAT_DIR_TYPE_EMPTY:
      break;
    default:
      clib_warning ("Unknown value %d\n", res[ii].type);
      break;
    }
  }
  stat_segment_data_free(res);
  vec_free(stats);
  // send the structure via netlink
  SFLOWUSSpec spec = {};
  SFLOWUSSpec_setAttrInt(&spec, SFLOWUS_ATTR_IFINDEX, sfif->hw_if_index);
  SFLOWUSSpec_setAttr(&spec, SFLOWUS_ATTR_PORTNAME, hw->name, strlen((char *)hw->name));
  SFLOWUSSpec_setAttr(&spec, SFLOWUS_ATTR_COUNTERS_GENERIC, &ifCtrs, sizeof(ifCtrs));
  SFLOWUSSpec_send(&smp->sflow_usersock, &spec);
}

/* Action function shared between message handler and debug CLI */
static void *spt_process_samples(void *ctx) {
  sflow_main_t *smp = (sflow_main_t *)ctx;
  vlib_set_thread_name("sflow");
  struct timespec ts = { .tv_sec = 0, .tv_nsec = 1000 };
  
  while(smp->running) {
    struct timespec now_mono;
    clock_gettime (CLOCK_MONOTONIC, &now_mono);
    if(now_mono.tv_sec != smp->now_mono_S) {
      // second rollover
      smp->now_mono_S = now_mono.tv_sec;
      // see if we should poll one or more interfaces
      for(int ii = 0; ii < vec_len(smp->main_per_interface_data); ii++) {
	sflow_main_per_interface_data_t *sfif = vec_elt_at_index(smp->main_per_interface_data, ii);
	if(sfif
	   && sfif->sflow_enabled
	   && (smp->now_mono_S % smp->pollingS) == (sfif->hw_if_index % smp->pollingS)) {
	  update_counters(smp, sfif);
	}
      }
    }
    
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

static void init_worker_fifo(sflow_per_thread_data_t *sfwk) {
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

static void sflow_sampling_start(sflow_main_t *smp) {
  clib_warning("sflow_sampling_start");
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
      if(sfwk->fifo == NULL)
	init_worker_fifo(sfwk);
      clib_warning("sflow startup: samplingN=%u thread=%u skip=%u",
		   smp->samplingN,
		   thread_index,
		   sfwk->skip);
    }
  }
  
  /* Some per-thread numbers are maintained only in the main thread. */
  vec_validate (smp->main_per_thread_data, smp->total_threads);

  /* open PSAMPLE netlink channel for writing packet samples */
  SFLOWPS_open(&smp->sflow_psample);
  /* open USERSOCK netlink channel for writing counters */
  SFLOWUS_open(&smp->sflow_usersock);
  // TODO: decide on this:
  smp->sflow_usersock.group_id = SFLOW_NETLINK_USERSOCK_MULTICAST;

  /* fork sample-processing thread */
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, VLIB_THREAD_STACK_SIZE);
  pthread_create(&smp->spthread, &attr, spt_process_samples, smp);
  
  clib_warning("sflow_sampling_start done");
}
      
static void sflow_sampling_stop(sflow_main_t *smp) {
  clib_warning("sflow_sampling_stop");
  /* TODO: Setting smp->running to 0 should trigger clean exit from spthread
     so we can pthread_join() - but if it is blocked then this will
     never return so perhaps we should pthread_cancel() it instead? */
  smp->running = 0;
  SFLOWPS_close(&smp->sflow_psample);
  SFLOWUS_close(&smp->sflow_usersock);
  //pthread_cancel(smp->spthread, NULL);
  pthread_join(smp->spthread, NULL);
  clib_warning("sflow_sampling_stop_done");
}

static void sflow_sampling_start_stop(sflow_main_t *smp) {
  int run = (smp->samplingN != 0
	     && smp->interfacesEnabled != 0);
  if(run != smp->running) {
    if(run)
      sflow_sampling_start(smp);
    else
      sflow_sampling_stop(smp);
  }
}

int sflow_sampling_rate (sflow_main_t * smp, u32 samplingN)
{
  smp->samplingN = samplingN;
  sflow_sampling_start_stop(smp);
  return 0;
}

int sflow_polling_interval (sflow_main_t * smp, u32 pollingS)
{
  smp->pollingS = pollingS;
  // TODO: reschedule ports?
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

  // note: vnet_interface_main_t has "fast lookup table" called
  // he_if_index_by_sw_if_index.
  clib_warning("sw_if_index=%u, sup_sw_if_index=%u, hw_if_index=%u\n",
	       sw->sw_if_index,
	       sw->sup_sw_if_index,
	       sw->hw_if_index);
  for(int ii = 0; ii < VNET_N_MTU; ii++)
    clib_warning("mtu[%u]=%u\n", ii, sw->mtu[ii]);

  // note: vnet_hw_interface_t has uword *bond_info
  // (where 0=>none, ~0 => slave, other=>ptr to bitmap of slaves)

  vec_validate (smp->main_per_interface_data, sw->hw_if_index);
  sflow_main_per_interface_data_t *sfif = vec_elt_at_index(smp->main_per_interface_data, sw->hw_if_index);
  if(enable_disable == sfif->sflow_enabled) {
    // redundant enable or disable
    // TODO: decide which error for (a) redundant enable and (b) redundant disable
    return VNET_API_ERROR_VALUE_EXIST;
  }
  else {
    // OK, turn it on/off
    sfif->sflow_enabled = enable_disable;
    vnet_feature_enable_disable ("device-input", "sflow", sw_if_index, enable_disable, 0, 0);
    smp->interfacesEnabled += (enable_disable) ? 1 : -1;
  }
  
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
sflow_polling_interval_command_fn (vlib_main_t * vm,
				   unformat_input_t * input,
				   vlib_cli_command_t * cmd)
{
  sflow_main_t * smp = &sflow_main;
  u32 polling_S = ~0;

  int rv;

  while (unformat_check_input (input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (input, "%u", &polling_S))
	;
      else
        break;
    }
  
  if (polling_S == ~0)
    return clib_error_return (0, "Please specify a polling interval...");

  rv = sflow_polling_interval (smp, polling_S);

  switch(rv)
    {
    case 0:
      break;
    default:
      return clib_error_return (0, "sflow_polling_interval returned %d",
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

VLIB_CLI_COMMAND (sflow_polling_interval_command, static) =
  {
    .path = "sflow polling-interval",
    .short_help = "sflow polling-interval <S>",
    .function = sflow_polling_interval_command_fn,
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

static void vl_api_sflow_polling_interval_t_handler
(vl_api_sflow_polling_interval_t * mp)
{
  vl_api_sflow_polling_interval_reply_t * rmp;
  sflow_main_t * smp = &sflow_main;
  int rv;
  
  rv = sflow_polling_interval (smp,
			       ntohl(mp->polling_S));
  
  REPLY_MACRO(VL_API_SFLOW_POLLING_INTERVAL_REPLY);
}

/* API definitions */
#include <sflow/sflow.api.c>

static clib_error_t * sflow_init (vlib_main_t * vm)
{
  sflow_main_t * smp = &sflow_main;
  clib_error_t * error = 0;

  smp->vlib_main = vm;
  smp->vnet_main = vnet_get_main();

  /* set default sampling-rate and polling-interval so that "enable" is all that is necessary */
  smp->samplingN = SFLOW_DEFAULT_SAMPLING_N;
  smp->pollingS = SFLOW_DEFAULT_POLLING_S;
  
  /* TODO: make this a CLI parameter too */
  smp->header_bytes = SFLOW_DEFAULT_HEADER_BYTES;

  /* Add our API messages to the global name_crc hash table */
  smp->msg_id_base = setup_message_id_table ();

  /* access to counters - TODO: should this only happen on sflow enable? */
  sflow_stat_segment_client_init();
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
