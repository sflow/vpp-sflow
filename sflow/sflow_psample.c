/*
  MIT License

  Copyright (c) 2021 sflow

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.
*/

#if defined(__cplusplus)
extern "C" {
#endif

#include <vlib/vlib.h>
#include <vnet/vnet.h>
#include <vnet/pg/pg.h>
#include <vppinfra/error.h>
#include <sflow/sflow.h>

#include <fcntl.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/psample.h>
#include <signal.h>
#include <ctype.h>

#include <sflow/sflow_psample.h>


  /*_________________---------------------------__________________
    _________________       fcntl utils         __________________
    -----------------___________________________------------------
  */

  static void setNonBlocking(int fd) {
    // set the socket to non-blocking
    int fdFlags = fcntl(fd, F_GETFL);
    fdFlags |= O_NONBLOCK;
    if(fcntl(fd, F_SETFL, fdFlags) < 0) {
      clib_warning("fcntl(O_NONBLOCK) failed: %s\n", strerror(errno));
    }
  }

  static void setCloseOnExec(int fd) {
    // make sure it doesn't get inherited, e.g. when we fork a script
    int fdFlags = fcntl(fd, F_GETFD);
    fdFlags |= FD_CLOEXEC;
    if(fcntl(fd, F_SETFD, fdFlags) < 0) {
      clib_warning("fcntl(F_SETFD=FD_CLOEXEC) failed: %s\n", strerror(errno));
    }
  }

  /*_________________---------------------------__________________
    _________________        generic_pid        __________________
    -----------------___________________________------------------
    choose a 32-bit id that is likely to be unique even if more
    than one module in this process wants to bind a netlink socket
  */

  static u32 generic_pid(u32 mod_id) {
    return (mod_id << 16) | getpid();
  }

  /*_________________---------------------------__________________
    _________________        generic_open       __________________
    -----------------___________________________------------------
  */

  static int generic_open(u32 mod_id) {
    int nl_sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_GENERIC);
    if(nl_sock < 0) {
      clib_warning("nl_sock open failed: %s\n", strerror(errno));
      return -1;
    }
    // bind to a suitable id
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK,
      .nl_pid = generic_pid(mod_id) };
    if(bind(nl_sock, (struct sockaddr *)&sa, sizeof(sa)) < 0)
      clib_warning("generic_open: bind failed: %s\n", strerror(errno));
    setNonBlocking(nl_sock);
    setCloseOnExec(nl_sock);
    return nl_sock;
  }

  /*_________________---------------------------__________________
    _________________       generic_send        __________________
    -----------------___________________________------------------
  */

  static int generic_send(int sockfd, u32 mod_id, int type, int cmd, int req_type, void *req, int req_len, u32 seqNo) {
    struct nlmsghdr nlh = { };
    struct genlmsghdr ge = { };
    struct nlattr attr = { };
    int req_footprint = NLMSG_ALIGN(req_len);

    attr.nla_len = sizeof(attr) + req_len;
    attr.nla_type = req_type;

    ge.cmd = cmd;
    ge.version = 1;

    nlh.nlmsg_len = NLMSG_LENGTH(req_footprint + sizeof(attr) + sizeof(ge));
    nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh.nlmsg_type = type;
    nlh.nlmsg_seq = seqNo;
    nlh.nlmsg_pid = generic_pid(mod_id);

    struct iovec iov[4] = {
      { .iov_base = &nlh,  .iov_len = sizeof(nlh) },
      { .iov_base = &ge,   .iov_len = sizeof(ge) },
      { .iov_base = &attr, .iov_len = sizeof(attr) },
      { .iov_base = req,   .iov_len = req_footprint }
    };

    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct msghdr msg = { .msg_name = &sa, .msg_namelen = sizeof(sa), .msg_iov = iov, .msg_iovlen = 4 };
    return sendmsg(sockfd, &msg, 0);
  }


  /*_________________---------------------------__________________
    _________________    getFamily_PSAMPLE      __________________
    -----------------___________________________------------------
  */

  static void getFamily_PSAMPLE(SFLOWPS *pst)
  {
    clib_warning("getFamily\n");
    generic_send(pst->nl_sock,
		 pst->id,
		 GENL_ID_CTRL,
		 CTRL_CMD_GETFAMILY,
		 CTRL_ATTR_FAMILY_NAME,
		 PSAMPLE_GENL_NAME,
		 sizeof(PSAMPLE_GENL_NAME)+1,
		 ++pst->nl_seq);
  }

  /*_________________---------------------------__________________
    _________________  processNetlink_GENERIC   __________________
    -----------------___________________________------------------
  */

  static void processNetlink_GENERIC(SFLOWPS *pst, struct nlmsghdr *nlh)
  {
    char *msg = (char *)NLMSG_DATA(nlh);
    int msglen = nlh->nlmsg_len - NLMSG_HDRLEN;
    struct genlmsghdr *genl = (struct genlmsghdr *)msg;
    clib_warning("generic netlink CMD = %u\n", genl->cmd);

    for(int offset = GENL_HDRLEN; offset < msglen; ) {
      struct nlattr *attr = (struct nlattr *)(msg + offset);
      if(attr->nla_len == 0 ||
	 (attr->nla_len + offset) > msglen) {
	clib_warning("processNetlink_GENERIC attr parse error\n");
	break; // attr parse error
      }
      char *attr_datap = (char *)attr + NLA_HDRLEN;
      switch(attr->nla_type) {
      case CTRL_ATTR_VERSION:
	pst->genetlink_version = *(u32 *)attr_datap;
	break;
      case CTRL_ATTR_FAMILY_ID:
	pst->family_id = *(u16 *)attr_datap;
	clib_warning("generic family id: %u\n", pst->family_id); 
	break;
      case CTRL_ATTR_FAMILY_NAME:
	clib_warning("generic family name: %s\n", attr_datap); 
	break;
      case CTRL_ATTR_MCAST_GROUPS:
	for(int grp_offset = NLA_HDRLEN; grp_offset < attr->nla_len;) {
	  struct nlattr *grp_attr = (struct nlattr *)(msg + offset + grp_offset);
	  if(grp_attr->nla_len == 0 ||
	     (grp_attr->nla_len + grp_offset) > attr->nla_len) {
	    clib_warning("processNetlink_GENERIC grp_attr parse error\n");
	    break;
	  }
	  char *grp_name=NULL;
	  u32 grp_id=0;
	  for(int gf_offset = NLA_HDRLEN; gf_offset < grp_attr->nla_len; ) {
	    struct nlattr *gf_attr = (struct nlattr *)(msg + offset + grp_offset + gf_offset);
	    if(gf_attr->nla_len == 0 ||
	       (gf_attr->nla_len + gf_offset) > grp_attr->nla_len) {
	      clib_warning("processNetlink_GENERIC gf_attr parse error\n");
	      break;
	    }
	    char *grp_attr_datap = (char *)gf_attr + NLA_HDRLEN;
	    switch(gf_attr->nla_type) {
	    case CTRL_ATTR_MCAST_GRP_NAME:
	      grp_name = grp_attr_datap;
	      clib_warning("psample multicast group: %s\n", grp_name); 
	      break;
	    case CTRL_ATTR_MCAST_GRP_ID:
	      grp_id = *(u32 *)grp_attr_datap;
	      clib_warning("psample multicast group id: %u\n", grp_id); 
	      break;
	    }
	    gf_offset += NLMSG_ALIGN(gf_attr->nla_len);
	  }
	  if(pst->group_id == 0
	     && grp_name
	     && grp_id
	     && !strcmp(grp_name, PSAMPLE_NL_MCGRP_SAMPLE_NAME)) {
	    clib_warning("psample found group %s=%u\n", grp_name, grp_id);
	    pst->group_id = grp_id;
	    // We don't need to join the group if we are only sending to it.
	  }

	  grp_offset += NLMSG_ALIGN(grp_attr->nla_len);
	}
	break;
      default:
	clib_warning("psample attr type: %u (nested=%u) len: %u\n",
		     attr->nla_type,
		     attr->nla_type & NLA_F_NESTED,
		     attr->nla_len);
      }
      offset += NLMSG_ALIGN(attr->nla_len);
    }
  }

  /*_________________---------------------------__________________
    _________________      processNetlink       __________________
    -----------------___________________________------------------
  */

  static void processNetlink(SFLOWPS *pst, struct nlmsghdr *nlh)
  {
    if(nlh->nlmsg_type == NETLINK_GENERIC) {
      processNetlink_GENERIC(pst, nlh);
    }
    else if(nlh->nlmsg_type == pst->family_id) {
      // We are write-only, don't need to read these.
    }
  }

  /*_________________---------------------------__________________
    _________________   readNetlink_PSAMPLE     __________________
    -----------------___________________________------------------
  */

#define SFLOWPS_PSAMPLE_READNL_RCV_BUF 8192
#define SFLOWPS_PSAMPLE_READNL_BATCH 10
  
  static void readNetlink_PSAMPLE(SFLOWPS *pst, int fd)
  {
    uint8_t recv_buf[SFLOWPS_PSAMPLE_READNL_RCV_BUF];
    int batch = 0;
    for( ; batch < SFLOWPS_PSAMPLE_READNL_BATCH; batch++) {
      int numbytes = recv(fd, recv_buf, sizeof(recv_buf), 0);
      if(numbytes <= 0)
	break;
      struct nlmsghdr *nlh = (struct nlmsghdr*) recv_buf;
      while(NLMSG_OK(nlh, numbytes)){
	if(nlh->nlmsg_type == NLMSG_DONE)
	  break;
	if(nlh->nlmsg_type == NLMSG_ERROR){
	  struct nlmsgerr *err_msg = (struct nlmsgerr *)NLMSG_DATA(nlh);
	  if(err_msg->error == 0) {
	    clib_warning("received Netlink ACK\n");
	  }
	  else {
	    // TODO: parse NLMSGERR_ATTR_OFFS to get offset?  Might be helpful
	    clib_warning("error in netlink message: %d : %s\n",
			 err_msg->error,
			 strerror(-err_msg->error));
	  }
	  break;
	}
	processNetlink(pst, nlh);
	nlh = NLMSG_NEXT(nlh, numbytes);
      }
    }
  }

  /*_________________---------------------------__________________
    _________________       socketRead          __________________
    -----------------___________________________------------------
  */

  typedef void (*SFLOWPSReadCB)(SFLOWPS *pst, int sock);

  static void socketRead(SFLOWPS *pst, u32 select_mS, SFLOWPSReadCB readCB) {
    fd_set readfds;
    FD_ZERO(&readfds);
    sigset_t emptyset;
    sigemptyset(&emptyset);
    FD_SET(pst->nl_sock, &readfds);
    int max_fd = pst->nl_sock;
    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = select_mS * 1000000;
    int nfds = pselect(max_fd + 1,
		       &readfds,
		       (fd_set *)NULL,
		       (fd_set *)NULL,
		       &timeout,
		       &emptyset);
    // see if we got anything
    if(nfds > 0) {
      if(FD_ISSET(pst->nl_sock, &readfds))
	(*readCB)(pst, pst->nl_sock);
    }
    else if(nfds < 0) {
      // may return prematurely if a signal was caught, in which case nfds will be
      // -1 and errno will be set to EINTR.  If we get any other error, bail.
      if(errno != EINTR) {
	clib_warning("pselect() returned %d : %s\n", nfds, strerror(errno));
      }
    }
  }


  /*_________________---------------------------__________________
    _________________       SFLOWPS_open        __________________
    -----------------___________________________------------------
  */
  
  bool SFLOWPS_open(SFLOWPS *pst) {
    if(pst->nl_sock == 0) {
      pst->nl_sock = generic_open(pst->id);
      getFamily_PSAMPLE(pst);
      socketRead(pst, 500, readNetlink_PSAMPLE);
      if(pst->family_id == 0) {
	clib_warning("failed to get PSAMPLE family id\n");
	return false;
      }
    }
    return true;
  }

  /*_________________---------------------------__________________
    _________________       SFLOWPS_close       __________________
    -----------------___________________________------------------
  */
  
  bool SFLOWPS_close(SFLOWPS *pst) {
    if(pst->nl_sock != 0) {
      int err = close(pst->nl_sock);
      if(err == 0) {
	pst->nl_sock = 0;
	return true;
      }
      else {
	clib_warning("SFLOWPS_close: returned %d : %s\n", err, strerror(errno));
      }
    }
    return false;
  }

  /*_________________---------------------------__________________
    _________________    SFLOWPSSpec_setAttr    __________________
    -----------------___________________________------------------
  */
  
  bool SFLOWPSSpec_setAttr(SFLOWPSSpec *spec, EnumSFLOWPSAttributes field, void *val, int len) {
    SFLOWPSAttr *psa = &spec->attr[field];
    if(psa->included)
      return false;
    psa->included = true;
    int expected_len = SFLOWPS_Fields[field].len;
    if(expected_len
       && expected_len != len)
      return false;
    psa->attr.nla_type = field;
    psa->attr.nla_len = sizeof(psa->attr) + len;
    int len_w_pad = NLMSG_ALIGN(len);
    psa->val.iov_len = len_w_pad;
    psa->val.iov_base = val;
    spec->n_attrs++;
    spec->attrs_len += sizeof(psa->attr);
    spec->attrs_len += len_w_pad;
    return true;
  }

  /*_________________---------------------------__________________
    _________________    SFLOWPSSpec_send       __________________
    -----------------___________________________------------------
  */

  int SFLOWPSSpec_send(SFLOWPS *pst, SFLOWPSSpec *spec) {
    // clib_warning("send_psample getuid=%d geteuid=%d\n", getuid(), geteuid());

    spec->nlh.nlmsg_len = NLMSG_LENGTH(sizeof(spec->ge) + spec->attrs_len);
    spec->nlh.nlmsg_flags = 0;
    spec->nlh.nlmsg_type = pst->family_id;
    spec->nlh.nlmsg_seq = ++pst->nl_seq;
    spec->nlh.nlmsg_pid = generic_pid(pst->id);

    spec->ge.cmd = PSAMPLE_CMD_SAMPLE;
    spec->ge.version = PSAMPLE_GENL_VERSION;


#define MAX_IOV_FRAGMENTS (2 * __SFLOWPS_PSAMPLE_ATTR_MAX) + 2

    struct iovec iov[MAX_IOV_FRAGMENTS];
    u32 frag = 0;
    iov[frag].iov_base = &spec->nlh;
    iov[frag].iov_len = sizeof(spec->nlh);
    frag++;
    iov[frag].iov_base = &spec->ge;
    iov[frag].iov_len = sizeof(spec->ge);
    frag++;
    int nn = 0;
    for(u32 ii = 0; ii < __SFLOWPS_PSAMPLE_ATTR_MAX; ii++) {
      SFLOWPSAttr *psa = &spec->attr[ii];
      if(psa->included) {
	nn++;
	iov[frag].iov_base = &psa->attr;
	iov[frag].iov_len = sizeof(psa->attr);
	frag++;
	iov[frag] = psa->val; // struct copy
	frag++;
      }
    }
    ASSERT(nn == spec->n_attrs);

    struct sockaddr_nl sa = {
      .nl_family = AF_NETLINK,
      .nl_groups = (1 << (pst->group_id-1))
    };

    struct msghdr msg = {
      .msg_name = &sa,
      .msg_namelen = sizeof(sa),
      .msg_iov = iov,
      .msg_iovlen = frag
    };

    int status = sendmsg(pst->nl_sock, &msg, 0);
    // clib_warning("sendmsg returned %d\n", status);
    if (status <= 0) {
      if (errno != EMSGSIZE)
        clib_warning("strerror(errno) = %s; errno = %d\n", strerror(errno), errno);
      return -1;
    }
    return 0;
  }
