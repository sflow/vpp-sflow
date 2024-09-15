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

/* sFlow Generic interface counters - see RFC 1573, 2233 */
typedef struct {
  u32 ifIndex;
  u32 ifType;
  u64 ifSpeed;
  u32 ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  u32 ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  u64 ifInOctets;
  u32 ifInUcastPkts;
  u32 ifInMulticastPkts;
  u32 ifInBroadcastPkts;
  u32 ifInDiscards;
  u32 ifInErrors;
  u32 ifInUnknownProtos;
  u64 ifOutOctets;
  u32 ifOutUcastPkts;
  u32 ifOutMulticastPkts;
  u32 ifOutBroadcastPkts;
  u32 ifOutDiscards;
  u32 ifOutErrors;
  u32 ifPromiscuousMode;
} SFL_if_counters_t;

#define SFLSTATUS_ADMIN_UP 1
#define SFLSTATUS_OPER_UP 2
  /* LAG Port Statistics - see IEEE8023-LAG-MIB */
  /* opaque = counter_data; enterprise = 0; format = 7 */
typedef  union {
    u32 all;
    struct {
      u8 actorAdmin;
      u8 actorOper;
      u8 partnerAdmin;
      u8 partnerOper;
    } v;
} SFL_LACP_portState_t;

typedef struct {
  u8 actorSystemID[8]; // 6 bytes + 2 pad
  u8 partnerSystemID[8]; // 6 bytes + 2 pad
  u32 attachedAggID;
  SFL_LACP_portState_t portState;
  u32 LACPDUsRx;
  u32 markerPDUsRx;
  u32 markerResponsePDUsRx;
  u32 unknownRx;
  u32 illegalRx;
  u32 LACPDUsTx;
  u32 markerPDUsTx;
  u32 markerResponsePDUsTx;
} SFL_LACP_counters_t;

/* port name */
#define SFL_MAX_PORTNAME_LEN 255
typedef struct {
  u32 portNameLen;
  u8 portName[SFL_MAX_PORTNAME_LEN];
} SFL_portName_t;

// Selected standard sflow counter structure tag numbers:
// See https://sflow.org
typedef enum {
  SFLCOUNTERS_GENERIC       = 1,
  SFLCOUNTERS_LACP          = 7,
  SFLCOUNTERS_PORTNAME      = 1005,
} SFL_counters_type_tag;

typedef enum {
#define SFLOWUS_FIELDDATA(field, tag, len, descr) field,
#include "sflow/sflow_usersock_fields.h"
#undef SFLOWUS_FIELDDATA
  __SFLOWUS_ATTR_MAX
} EnumSFLOWUSAttributes;
  
typedef struct _SFLOWUS_field_t {
  EnumSFLOWUSAttributes field;
  SFL_counters_type_tag sflow_tag;
  int len;
  char *descr;
} SFLOWUS_field_t;

static const SFLOWUS_field_t SFLOWUS_Fields[] = {
#define SFLOWUS_FIELDDATA(field, tag, len, descr) {field, tag, len, descr },
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

bool SFLOWUSSpec_setAttr(SFLOWUSSpec *spec, EnumSFLOWUSAttributes field, void *buf, int len);
#define SFLOWUSSpec_setAttrInt(spec, field, val) SFLOWUSSpec_setAttr((spec), (field), &(val), sizeof(val))

void SFLOWUSSpec_send(SFLOWUS *ust, SFLOWUSSpec *spec);

#endif  /* __included_sflow_usersock_h__ */
