/*
** tracing.c - Seccomp wrapper around syscall tracing
**
** Copyright (c) Uchio Kondo 2016
**
** See Copyright Notice in LICENSE
*/

#include "mrb_seccomp.h"

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>

/* At CentOS 7 there seems no definition */
#ifndef PTRACE_EVENT_SECCOMP
#define PTRACE_EVENT_SECCOMP 7
#endif

#ifdef MRB_SECCOMP_DEBUG
#define _log_p(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define _log_p(fmt, ...)                                                                                               \
  if (0)                                                                                                               \
  printf(fmt, ##__VA_ARGS__)
#endif

#define MRB_PTRACE_DEFAULT_OPT                                                                                         \
  (PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEEXIT | PTRACE_O_TRACESECCOMP)

static void mrb_seccomp_userdata_free(mrb_state *mrb, void *p)
{
  uint16_t *data = (uint16_t *)p;
  if (data)
    mrb_free(mrb, data);
}

static const struct mrb_data_type mrb_seccomp_tracer_type = {
    "mrb_seccomp_tracer_data", mrb_seccomp_userdata_free,
};

static mrb_value mrb_seccomp_tracer_init(mrb_state *mrb, mrb_value self)
{
  mrb_int userdata;
  uint16_t *value = mrb_malloc(mrb, sizeof(uint16_t));

  mrb_get_args(mrb, "i", &userdata);
  DATA_TYPE(self) = &mrb_seccomp_tracer_type;

  value[0] = (uint16_t)userdata;
  DATA_PTR(self) = value;

  return self;
}

uint32_t mrb_seccomp_tracer_to_action(mrb_state *mrb, mrb_value self)
{
  uint16_t *userdata = (uint16_t *)DATA_PTR(self);
  if (!userdata) {
    mrb_sys_fail(mrb, "[BUG] userdata is NULL");
  }
  return SCMP_ACT_TRACE(userdata[0]);
}

static int mrb_seccomp_on_tracer_trap(mrb_state *mrb, mrb_value hook, pid_t child, int detach)
{
  unsigned long msg;
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg) != 0) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_GETEVENTMSG...");
  }
  if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_GETREGS...");
  }
  if (detach) {
    ptrace(PTRACE_DETACH, child, NULL, NULL);
  }
  mrb_value args[3];
  args[0] = mrb_fixnum_value((int)regs.orig_rax); // syscall no
  args[1] = mrb_fixnum_value((int)child);         // pid
  args[2] = mrb_fixnum_value((int)msg);           // userdata
  mrb_yield_argv(mrb, hook, 3, args);
  return 0;
}

static int mrb_seccomp_on_tracer_fork(mrb_state *mrb, pid_t child)
{
  unsigned long msg;
  pid_t pid;

  if (ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg) != 0) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_GETEVENTMSG...");
  }
  pid = (pid_t)msg;
  _log_p("Debug: tracing pid %d\n", pid);

  return 0;
}

#define MRB_PTRACE_EVENT(status) (((status >> 8) ^ SIGTRAP) >> 8)

/* This method is implemented unser Seccomp root module */
static mrb_value mrb_seccomp_start_ptrace(mrb_state *mrb, mrb_value self, int detach)
{
  mrb_int pid;
  mrb_value hook;
  int status, child;
  mrb_get_args(mrb, "i&", &pid, &hook);
  if (ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == -1) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_ATTACH...");
  }
  waitpid(pid, &status, 0);

  if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)MRB_PTRACE_DEFAULT_OPT) == -1) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_SETOPTIONS...");
  }
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_CONT...");
  }

  int children_exit = FALSE;
  while (1) {
    child = waitpid(-1, &status, WUNTRACED | WCONTINUED | __WALL);
    if (child == -1) {
      mrb_sys_fail(mrb, "waitpid");
    }

    if (WIFEXITED(status)) {
      if (child == pid) {
        return mrb_str_new_lit(mrb, "exited");
      } else {
        children_exit = TRUE;
      }
    } else if (WIFSIGNALED(status)) {
      if (child == pid) {
        return mrb_str_new_lit(mrb, "signaled");
      } else {
        children_exit = TRUE;
      }
    } else if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGTRAP) {
        if (MRB_PTRACE_EVENT(status) == PTRACE_EVENT_FORK || MRB_PTRACE_EVENT(status) == PTRACE_EVENT_VFORK) {
          _log_p("Debug: fork is invoked\n");
          if (mrb_seccomp_on_tracer_fork(mrb, child) < 0) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "Something is wrong when grandchildren fork");
          }
        } else if (MRB_PTRACE_EVENT(status) == PTRACE_EVENT_SECCOMP) {
          if (mrb_seccomp_on_tracer_trap(mrb, hook, child, detach) < 0) {
            mrb_raise(mrb, E_RUNTIME_ERROR, "Something is wrong in trap event");
          }
          if (detach) {
            return self;
          }
        }
      }
    } else if (WIFCONTINUED(status)) {
      /* noop */
    } else {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "Got unknown event: %x", status);
    }

    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
      if (!children_exit) {
        mrb_raisef(mrb, E_RUNTIME_ERROR, "Cannot continue process: %d. Force to kill", mrb_fixnum_value(child));
      }
    }
    children_exit = FALSE;
  }
}
static mrb_value mrb_seccomp_ptrace(mrb_state *mrb, mrb_value self)
{
  return mrb_seccomp_start_ptrace(mrb, self, FALSE);
}

static mrb_value mrb_seccomp_ptrace_detach(mrb_state *mrb, mrb_value self)
{
  return mrb_seccomp_start_ptrace(mrb, self, TRUE);
}

void mrb_mruby_seccomp_tracing_init(mrb_state *mrb, struct RClass *parent)
{
  struct RClass *tracer = mrb_define_class_under(mrb, parent, "Tracer", mrb->object_class);
  MRB_SET_INSTANCE_TT(tracer, MRB_TT_DATA);
  mrb_define_method(mrb, tracer, "initialize", mrb_seccomp_tracer_init, MRB_ARGS_REQ(1));
  mrb_define_module_function(mrb, parent, "start_trace", mrb_seccomp_ptrace, MRB_ARGS_REQ(1) | MRB_ARGS_BLOCK());
  mrb_define_module_function(mrb, parent, "start_trace_detach", mrb_seccomp_ptrace_detach,
                             MRB_ARGS_REQ(1) | MRB_ARGS_BLOCK());
}
