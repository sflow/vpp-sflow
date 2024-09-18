#ifndef __included_sflow_usersock_h__
#define __included_sflow_usersock_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <signal.h>
#include <ctype.h>

typedef enum {
  SFLOWUS_STATUS=1,
  SFLOWUS_IF_COUNTERS
  /* shared with hsflowd so only add here */
} EnumSFLOWUSMsgType;

typedef struct {
  u64 byts;
  u64 u_pkts;
  u64 m_pkts;
  u64 b_pkts;
  u64 errs;
  u64 drps;
} sflow_ctrs_t;

typedef struct {
  sflow_ctrs_t tx;
  sflow_ctrs_t rx;
} sflow_counters_t;

// TODO: share structs+code with sflow_psample.h

typedef enum {
#define SFLOWUS_FIELDDATA(field, len, descr) field,
#include "sflow/sflow_usersock_fields.h"
#undef SFLOWUS_FIELDDATA
  __SFLOWUS_ATTR_MAX
} EnumSFLOWUSAttributes;
  
typedef struct _SFLOWUS_field_t {
  EnumSFLOWUSAttributes field;
  int len;
  char *descr;
} SFLOWUS_field_t;

static const SFLOWUS_field_t SFLOWUS_Fields[] = {
#define SFLOWUS_FIELDDATA(field, len, descr) {field, len, descr },
#include "sflow/sflow_usersock_fields.h"
#undef SFLOWUS_FIELDDATA
};

typedef struct _SFLOWUS {
  u32 id;
  int nl_sock;
  u32 nl_seq;
  u32 group_id;
} SFLOWUS;

typedef struct _SFLOWUSAttr {
  bool included:1;
  struct nlattr attr;
  struct iovec val;
} SFLOWUSAttr;
    
typedef struct _SFLOWUSSpec {
  struct nlmsghdr nlh;
  SFLOWUSAttr attr[__SFLOWUS_ATTR_MAX];
  int n_attrs;
  int attrs_len;
} SFLOWUSSpec;

bool SFLOWUS_open(SFLOWUS *ust);
bool SFLOWUS_close(SFLOWUS *ust);

bool SFLOWUSSpec_setMsgType(SFLOWUSSpec *spec, EnumSFLOWUSMsgType type);
bool SFLOWUSSpec_setAttr(SFLOWUSSpec *spec, EnumSFLOWUSAttributes field, void *buf, int len);
#define SFLOWUSSpec_setAttrInt(spec, field, val) SFLOWUSSpec_setAttr((spec), (field), &(val), sizeof(val))

void SFLOWUSSpec_send(SFLOWUS *ust, SFLOWUSSpec *spec);

#endif  /* __included_sflow_usersock_h__ */
