#ifndef __included_sflow_psample_h__
#define __included_sflow_psample_h__

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/psample.h>
#include <signal.h>
#include <ctype.h>
  
/* Shadow the attributes in linux/psample.h so
 * we can easily compile/test fields that are not
 * defined on the kernel we are compiling on.
 */
typedef enum {
#define SFLOWPS_FIELDDATA(field, len, descr) field,
#include "sflow/sflow_psample_fields.h"
#undef SFLOWPS_FIELDDATA
  __SFLOWPS_PSAMPLE_ATTR_MAX
} EnumSFLOWPSAttributes;

typedef struct _SFLOWPS_field_t {
  EnumSFLOWPSAttributes field;
  int len;
  char *descr;
} SFLOWPS_field_t;

static const SFLOWPS_field_t SFLOWPS_Fields[] = {
#define SFLOWPS_FIELDDATA(field, len, descr) {field, len, descr },
#include "sflow/sflow_psample_fields.h"
#undef SFLOWPS_FIELDDATA
};

typedef struct _SFLOWPS {
  u32 id;
  int nl_sock;
  u32 nl_seq;
  u32 genetlink_version;
  u16 family_id;
  u32 group_id;
} SFLOWPS;

typedef struct _SFLOWPSAttr {
  bool included:1;
  struct nlattr attr;
  struct iovec val;
} SFLOWPSAttr;
    
typedef struct _SFLOWPSSpec {
  struct nlmsghdr nlh;
  struct genlmsghdr ge;
  SFLOWPSAttr attr[__SFLOWPS_PSAMPLE_ATTR_MAX];
  int n_attrs;
  int attrs_len;
} SFLOWPSSpec;

bool SFLOWPS_open(SFLOWPS *pst);
bool SFLOWPS_close(SFLOWPS *pst);

bool SFLOWPSSpec_setAttr(SFLOWPSSpec *spec, EnumSFLOWPSAttributes field, void *buf, int len);
#define SFLOWPSSpec_setAttrInt(spec, field, val) SFLOWPSSpec_setAttr((spec), (field), &(val), sizeof(val))

void SFLOWPSSpec_send(SFLOWPS *pst, SFLOWPSSpec *spec);

#endif  /* __included_sflow_psample_h__ */
