
/*
 * sflow_shm.h - shared memory counter export
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
#ifndef __included_sflow_shm_h__
#define __included_sflow_shm_h__

/* for shm_open(), mmap() and sem_wait() etc. */
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>

/* We'll bump this version number if we change the structures below. The version
 * is encoded in the name of the shared memory segment as well as in the header,
 * so it should be hard for a consumer to get out of sync.
 */
#define SFLOW_SHM_VERSION 1
#define STRINGIFY(Y) #Y
#define STRINGIFY_DEF(D) STRINGIFY(D)
#define SFLOW_SHM_PATH "/vpp-sflow-counters-" STRINGIFY_DEF(SFLOW_SHM_VERSION)
#define SFLOW_SHM_SIZE 2000000
#define SFLOW_MAX_PORTNAME_LEN 255

/* Shared memory port counters */
typedef struct {
  u64 ucasts;
  u64 mcasts;
  u64 bcasts;
  u64 bytes;
  u64 errs;
  u64 drops;
} sflow_shm_ctrs_t;

/* Shared memory ports */
typedef struct {
  u8 portName[SFLOW_MAX_PORTNAME_LEN+1];
  u32 hw_if_index;
  u32 linux_if_index;
  // TODO: populate these agg (bond) parent numbers too, where applicable.
  u32 vpp_agg_if_index;
  u32 linux_agg_if_index;
  sflow_shm_ctrs_t rx;
  sflow_shm_ctrs_t tx;
  u64 ifSpeed;
  u32 counter_updates;
} sflow_shm_port_t;

/* Shared memory header */
typedef struct {
  sem_t sem;
  u32 version;
  u32 max_port;
} sflow_shm_hdr_t;

#define SFLOW_SHM_PORT_NONE 0
#define SFLOW_SHM_MAX_PORTS (SFLOW_SHM_SIZE - sizeof(sflow_shm_hdr_t)) / sizeof(sflow_shm_port_t)
#define SFLOW_SHM_SIGN 0x5F106343
typedef struct {
  sflow_shm_hdr_t hdr;
  sflow_shm_port_t port[SFLOW_SHM_MAX_PORTS];
} sflow_shm_t;

#endif /* __included_sflow_shm_h__ */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * End:
 */

