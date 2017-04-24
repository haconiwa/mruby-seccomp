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

static void mrb_seccomp_userdata_free(mrb_state *mrb, void *p) {
  uint16_t *data = (uint16_t *)p;
  if (data)
    mrb_free(mrb, data);
}

static const struct mrb_data_type mrb_seccomp_tracer_type = {
    "mrb_seccomp_tracer_data", mrb_seccomp_userdata_free,
};

static mrb_value mrb_seccomp_tracer_init(mrb_state *mrb, mrb_value self) {
  mrb_int userdata;
  uint16_t *value = mrb_malloc(mrb, sizeof(uint16_t));

  mrb_get_args(mrb, "i", &userdata);
  DATA_TYPE(self) = &mrb_seccomp_tracer_type;

  value[0] = (uint16_t)userdata;
  DATA_PTR(self) = value;

  return self;
}

uint32_t mrb_seccomp_tracer_to_action(mrb_state *mrb, mrb_value self) {
  uint16_t *userdata = (uint16_t *)DATA_PTR(self);
  if (!userdata) {
    mrb_sys_fail(mrb, "[BUG] userdata is NULL");
  }
  return SCMP_ACT_TRACE(userdata[0]);
}

static int mrb_seccomp_on_tracer_trap(mrb_state *mrb, mrb_value hook,
                                      pid_t child) {
  unsigned long msg;
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETEVENTMSG, child, NULL, &msg) != 0) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_GETEVENTMSG...");
  }
  if (ptrace(PTRACE_GETREGS, child, NULL, &regs) != 0) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_GETREGS...");
  }

  mrb_value args[2];
  args[0] = mrb_fixnum_value((int)regs.orig_rax); // syscall no
  args[1] = mrb_fixnum_value((int)msg);           // userdata
  mrb_yield_argv(mrb, hook, 2, args);
  return 0;
}

#define MRB_PTRACE_EVENT(status) (((status >> 8) ^ SIGTRAP) >> 8)

/* This method is implemented unser Seccomp root module */
static mrb_value mrb_seccomp_start_ptrace(mrb_state *mrb, mrb_value self) {
  mrb_int pid;
  mrb_value hook;
  int status, child;
  mrb_get_args(mrb, "i&", &pid, &hook);
  if (ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == -1) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_ATTACH...");
  }
  waitpid(pid, &status, 0);

  if (ptrace(PTRACE_SETOPTIONS, pid, NULL, (void *)PTRACE_O_TRACESECCOMP) ==
      -1) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_SETOPTIONS...");
  }
  if (ptrace(PTRACE_CONT, pid, NULL, NULL) == -1) {
    mrb_sys_fail(mrb, "ptrace(PTRACE_CONT...");
  }

  child = pid;
  while (1) {
    child = waitpid(child, &status, WUNTRACED | WCONTINUED);
    if (child == -1) {
      mrb_sys_fail(mrb, "waitpid");
    }

    if (WIFEXITED(status)) {
      return mrb_str_new_lit(mrb, "exited");
    } else if (WIFSIGNALED(status)) {
      return mrb_str_new_lit(mrb, "signaled");
    } else if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGTRAP &&
          MRB_PTRACE_EVENT(status) == PTRACE_EVENT_SECCOMP) {
        if (mrb_seccomp_on_tracer_trap(mrb, hook, child) < 0) {
          mrb_raise(mrb, E_RUNTIME_ERROR, "Something is wrong in trap event");
        }
      }
    } else if (WIFCONTINUED(status)) {
      /* noop */
    } else {
      mrb_raisef(mrb, E_RUNTIME_ERROR, "Got unknown event: %x", status);
    }

    if (ptrace(PTRACE_CONT, child, NULL, NULL) < 0) {
      kill(child, SIGKILL);
      mrb_raisef(mrb, E_RUNTIME_ERROR,
                 "Cannot continue process: %d. Force to kill", child);
    }
  }
}

void mrb_mruby_seccomp_tracing_init(mrb_state *mrb, struct RClass *parent) {
  struct RClass *tracer =
      mrb_define_class_under(mrb, parent, "Tracer", mrb->object_class);
  MRB_SET_INSTANCE_TT(tracer, MRB_TT_DATA);
  mrb_define_method(mrb, tracer, "initialize", mrb_seccomp_tracer_init,
                    MRB_ARGS_REQ(1));

  mrb_define_module_function(mrb, parent, "start_trace",
                             mrb_seccomp_start_ptrace,
                             MRB_ARGS_REQ(1) | MRB_ARGS_BLOCK());
}
