
/*
 * sflow.h - sflow plug-in header file
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
#ifndef __included_sflow_h__
#define __included_sflow_h__

#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ethernet/ethernet.h>

#include <vppinfra/hash.h>
#include <vppinfra/error.h>
#include <svm/svm_fifo.h>
#include <svm/svm_common.h>
#include <svm/fifo_segment.h>
#include <sflow/sflow_psample.h>
#include <sflow/sflow_shm.h>

#define SFLOW_DEFAULT_SAMPLING_N 10000
#define SFLOW_DEFAULT_HEADER_BYTES 128
#define SFLOW_MAX_HEADER_BYTES 256
#define SFLOW_FIFO_SLICE 512
#define SFLOW_FIFO_SIZE 4096 * SFLOW_FIFO_SLICE

/* packet sample */
typedef struct {
  u32 samplingN;
  u32 input_if_index;
  u32 output_if_index;
  u32 header_protocol;
  u32 sampled_packet_size;
  u32 header_bytes;
  u32 thread_index;
  u32 thread_seqN;
  u32 thread_drop;
  u8 header[SFLOW_MAX_HEADER_BYTES];
} sflow_sample_t;

/* private to worker */
typedef struct {
  u32 smpN;
  u32 skip;
  u32 pool;
  u32 seed;
  u32 seqN;
  u32 drop;
  fifo_segment_main_t fsm;
  fifo_segment_t *fs;
  svm_fifo_t *fifo;
} sflow_per_thread_data_t;

/* private to main thread */
typedef struct {
  u32 seqN;
  u32 drop;
} sflow_main_per_thread_data_t;

/* private to main thread
   TODO: assuming polling is also moved to main thread */
typedef struct {
  u32 hw_if_index;
  int sflow_enabled;
  // TODO: possibly keep cache of counter index numbers here?
} sflow_main_per_interface_data_t;

typedef struct {
  /* API message ID base */
  u16 msg_id_base;
  
  /* convenience */
  vlib_main_t * vlib_main;
  vnet_main_t * vnet_main;
  ethernet_main_t * ethernet_main;

  /* sampling state */
  u32 samplingN;
  u32 header_bytes;
  u32 total_threads;
  u32 *per_thread_seqN;
  u32 *per_thread_drop;
  sflow_main_per_thread_data_t *main_per_thread_data;
  sflow_main_per_interface_data_t *main_per_interface_data;
  sflow_per_thread_data_t *per_thread_data;

  /* psample channel */
  SFLOWPS sflow_psample;

  /* sample-processing thread */
  pthread_t spthread;

  /* running control */
  int running;
  u32 interfacesEnabled;

  /* shared memory counter export */
#define SFLOW_SHM_SIZE 2000000
#ifdef SFLOW_TRY_WITH_SSVM
  ssvm_private_t ssvm;
#else
  sflow_shm_t *shmp;
#endif
} sflow_main_t;

extern sflow_main_t sflow_main;

extern vlib_node_registration_t sflow_node;

static inline u32 sflow_next_random_skip(sflow_per_thread_data_t *sfwk) {
  if(sfwk->smpN <= 1)
    return 1;
  return (random_u32(&sfwk->seed) % (2 * sfwk->smpN) - 1) + 1;
}

#endif /* __included_sflow_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

