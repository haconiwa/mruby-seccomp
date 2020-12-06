#include "mrb_seccomp.h"

#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <mruby/variable.h>

/*
 * See: https://man7.org/tlpi/code/online/dist/sockets/scm_functions.c.html
 * This source code is also provided unser GNU Lesser General Public License, version 3.
 */

#ifdef MRB_SECCOMP_NOTIF_ENABLED

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

static mrb_value mrb_seccomp_notif_init(mrb_state *mrb, mrb_value self)
{
  mrb_int notifyfd;
  mrb_get_args(mrb, "i", &notifyfd);
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@notify_fd"), mrb_fixnum_value(notifyfd));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@continue"), mrb_false_value());
  return self;
}

static mrb_value mrb_seccomp_notif_respond_internal(mrb_state *mrb, mrb_value self)
{
  struct seccomp_notif *req;
  struct seccomp_notif_resp *resp;
  mrb_value blk;
  mrb_value _fd = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@notify_fd"));
  int fd = mrb_fixnum(_fd);
  mrb_get_args(mrb, "&", &blk);

  int save = mrb_gc_arena_save(mrb);

  if(seccomp_notify_alloc(&req, &resp) == -1)
    mrb_sys_fail(mrb, "seccomp_notify_alloc");

  if(seccomp_notify_receive(fd, req) == -1)
    mrb_sys_fail(mrb, "seccomp_notify_receive");

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@pid"), mrb_fixnum_value(req->pid));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@notify_id"), mrb_float_value(mrb, req->id));
  /* TODO: handling req->data.args in a dynamic way... */

  mrb_value args = mrb_ary_new_capa(mrb, 6);
  for(mrb_int i = 0; i < 6; ++i )
    mrb_ary_set(mrb, args, i, mrb_float_value(mrb, req->data.args[i]));
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@raw_args"), args);

  mrb_yield(mrb, blk, self);

  mrb_value val, error;
  val = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@retval"));
  error = mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@reterror"));

  resp->id = req->id;

  if(mrb_bool(mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@continue")))) {
    #ifdef SECCOMP_USER_NOTIF_FLAG_CONTINUE
      resp->flags |= SECCOMP_USER_NOTIF_FLAG_CONTINUE;
    #else
      mrb_raise(mrb, E_NOTIMP_ERROR,
                "Seccomp::Notification#continue not supported on this system");
    #endif
  } else {
    if(mrb_nil_p(error))
      resp->error = 0;
    else
      resp->error = mrb_fixnum(error);

    resp->val = mrb_fixnum(val);
  }

  if(seccomp_notify_id_valid(fd, req->id) == -1) {
    seccomp_notify_free(req, resp);
    mrb_raise(mrb, mrb->eStandardError_class,
              "seccomp_notify_id_valid: maybe process already dead");
  }

  if(seccomp_notify_respond(fd, resp) == -1)
    mrb_sys_fail(mrb, "seccomp_notify_respond");

  seccomp_notify_free(req, resp);

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@pid"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@notify_id"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@raw_args"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@retval"), mrb_nil_value());
  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "@reterror"), mrb_nil_value());

  mrb_gc_arena_restore(mrb, save);

  return mrb_nil_value();
}

static mrb_value mrb_seccomp_notif_is_id_valid(mrb_state *mrb, mrb_value self)
{
  int fd = mrb_fixnum(mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@notify_fd")));
  int id = mrb_fixnum(mrb_iv_get(mrb, self, mrb_intern_lit(mrb, "@notify_id")));
  return mrb_bool_value(seccomp_notify_id_valid(fd, id));
}

/*
static mrb_value mrb_seccomp_ptrace(mrb_state *mrb, mrb_value self)
{
  return mrb_seccomp_start_ptrace(mrb, self, FALSE);
}
*/

void mrb_mruby_seccomp_notification_init(mrb_state *mrb, struct RClass *parent)
{
  struct RClass *notif = mrb_define_class_under(mrb, parent, "Notification", mrb->object_class);
  mrb_define_method(mrb, notif, "initialize", mrb_seccomp_notif_init, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, notif, "respond_internal", mrb_seccomp_notif_respond_internal, MRB_ARGS_BLOCK());
  mrb_define_method(mrb, notif, "id_valid?", mrb_seccomp_notif_is_id_valid, MRB_ARGS_NONE());

  mrb_define_module_function(mrb, parent, "sendfd", mrb_seccomp_util_sendfd, MRB_ARGS_REQ(2));
  mrb_define_module_function(mrb, parent, "recvfd", mrb_seccomp_util_recvfd, MRB_ARGS_REQ(1));
}

#else

void mrb_mruby_seccomp_notification_init(mrb_state *mrb, struct RClass *parent)
{
  /* No implementation */
}

#endif
