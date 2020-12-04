#include "mrb_seccomp.h"

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

/*
 * See: https://man7.org/tlpi/code/online/dist/sockets/scm_functions.c.html
 * This source code is also provided unser GNU Lesser General Public License, version 3.
 */
static mrb_value mrb_seccomp_util_sendfd(mrb_state *mrb, mrb_value self)
{
  struct msghdr msgh;
  struct iovec iov;
  char data[1];
  struct cmsghdr *cmsgp;
  char __msg[CMSG_SPACE(sizeof(int))];

  mrb_int _sockfd, _fd;
  mrb_get_args(mrb, "ii", &_sockfd, &_fd);
  int sockfd = _sockfd, fd = _fd;

  msgh.msg_name = NULL;
  msgh.msg_namelen = 0;
  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  iov.iov_base = data;
  iov.iov_len = sizeof(data);
  data[0] = '@';

  msgh.msg_control = __msg;
  msgh.msg_controllen = sizeof(__msg);

  cmsgp = CMSG_FIRSTHDR(&msgh);
  cmsgp->cmsg_level = SOL_SOCKET;
  cmsgp->cmsg_type = SCM_RIGHTS;
  cmsgp->cmsg_len = CMSG_LEN(sizeof(int));
  memcpy(CMSG_DATA(cmsgp), &fd, sizeof(int));

  if (sendmsg(sockfd, &msgh, 0) == -1)
    mrb_sys_fail(mrb, "sendmsg");

  return mrb_true_value();
}

static mrb_value mrb_seccomp_util_recvfd(mrb_state *mrb, mrb_value self)
{
  struct msghdr msgh;
  struct iovec iov;
  char data[1];
  int fd;
  struct cmsghdr *cmsgp;
  char __msg[CMSG_SPACE(sizeof(int))];

  mrb_int _sockfd;
  mrb_get_args(mrb, "i", &_sockfd);
  int sockfd = _sockfd;

  msgh.msg_name = NULL;
  msgh.msg_namelen = 0;

  msgh.msg_iov = &iov;
  msgh.msg_iovlen = 1;
  iov.iov_base = data; /* Receive dummy real data */
  iov.iov_len = sizeof(data);

  msgh.msg_control = __msg;
  msgh.msg_controllen = sizeof(__msg);

  if (recvmsg(sockfd, &msgh, 0) == -1)
    mrb_sys_fail(mrb, "recvmsg");

  cmsgp = CMSG_FIRSTHDR(&msgh);
  if (cmsgp == NULL ||
      cmsgp->cmsg_len != CMSG_LEN(sizeof(int)) ||
      cmsgp->cmsg_level != SOL_SOCKET ||
      cmsgp->cmsg_type != SCM_RIGHTS) {
    errno = EINVAL;
    mrb_sys_fail(mrb, "recvmsg received invalid data");
  }

  memcpy(&fd, CMSG_DATA(cmsgp), sizeof(int));
  return mrb_fixnum_value(fd);
}

/*
static mrb_value mrb_seccomp_ptrace(mrb_state *mrb, mrb_value self)
{
  return mrb_seccomp_start_ptrace(mrb, self, FALSE);
}
*/

void mrb_mruby_seccomp_notification_init(mrb_state *mrb, struct RClass *parent)
{
  mrb_define_module_function(mrb, parent, "sendfd", mrb_seccomp_util_sendfd, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, parent, "recvfd", mrb_seccomp_util_recvfd, MRB_ARGS_REQ(1));
}
