/*
** mrb_seccomp.c - Seccomp class
**
** Copyright (c) Uchio Kondo 2016
**
** See Copyright Notice in LICENSE
*/

#include <mruby.h>
#include <mruby/data.h>
#include <mruby/array.h>
#include <mruby/error.h>

#include <stdlib.h>
#include <seccomp.h>

#include "mrb_seccomp.h"

#define DONE mrb_gc_arena_restore(mrb, 0);

mrb_value mrb_seccomp_generate_syscall_table(mrb_state *mrb, mrb_value self);

typedef struct {
  scmp_filter_ctx ctx;
  uint32_t def_action;
} mrb_seccomp_data;

typedef struct {
  struct scmp_arg_cmp arg_cmp;
} mrb_seccomp_arg_cmp_data;

static void mrb_seccomp_free(mrb_state *mrb, void *p) {
  mrb_seccomp_data *data = (mrb_seccomp_data*)p;
  seccomp_release(data->ctx);
  mrb_free(mrb, data);
}

static void mrb_seccomp_arg_cmp_free(mrb_state *mrb, void *p) {
  mrb_seccomp_arg_cmp_data *data = (mrb_seccomp_arg_cmp_data*)p;
  mrb_free(mrb, data);
}

static const struct mrb_data_type mrb_seccomp_data_type = {
  "mrb_seccomp_data", mrb_seccomp_free,
};

static const struct mrb_data_type mrb_seccomp_arg_cmp_data_type = {
  "mrb_seccomp_arg_cmp_data", mrb_seccomp_arg_cmp_free,
};

static mrb_value mrb_seccomp_init(mrb_state *mrb, mrb_value self)
{
  mrb_seccomp_data *ctx_data;
  mrb_int def_action;

  ctx_data = (mrb_seccomp_data *)DATA_PTR(self);
  if (ctx_data) {
    mrb_seccomp_free(mrb, ctx_data);
  }
  DATA_TYPE(self) = &mrb_seccomp_data_type;
  DATA_PTR(self) = NULL;

  mrb_get_args(mrb, "i", &def_action);
  ctx_data = (mrb_seccomp_data *)mrb_malloc(mrb, sizeof(mrb_seccomp_data));
  ctx_data->ctx = seccomp_init((uint32_t)def_action);
  ctx_data->def_action = (uint32_t)def_action;
  DATA_PTR(self) = ctx_data;

  return self;
}

static mrb_value mrb_seccomp_arg_cmp_init(mrb_state *mrb, mrb_value self)
{
  mrb_seccomp_arg_cmp_data *ac_data;
  mrb_int index, op, datum_a, datum_b = -1;

  ac_data = (mrb_seccomp_arg_cmp_data *)DATA_PTR(self);
  if (ac_data) {
    mrb_seccomp_arg_cmp_free(mrb, ac_data);
  }
  DATA_TYPE(self) = &mrb_seccomp_arg_cmp_data_type;
  DATA_PTR(self) = NULL;

  mrb_get_args(mrb, "iii|i", &index, &op, &datum_a, &datum_b);
  ac_data = (mrb_seccomp_arg_cmp_data *)mrb_malloc(mrb, sizeof(mrb_seccomp_arg_cmp_data));
  if(datum_b < 0) {
    ac_data->arg_cmp = (SCMP_CMP((unsigned int)index, (int)op, (uint64_t)datum_a));
  } else {
    ac_data->arg_cmp = (SCMP_CMP((unsigned int)index, (int)op, (uint64_t)datum_a, (uint64_t)datum_b));
  }

  DATA_PTR(self) = ac_data;

  return self;
}

#define MRB_SECCOMP_CMP_FIND(a, i)                                      \
  (((mrb_seccomp_arg_cmp_data *)(DATA_PTR(mrb_ary_ref(mrb, a, i))))->arg_cmp)

static mrb_value mrb_seccomp_add_rule(mrb_state *mrb, mrb_value self)
{
  mrb_seccomp_data *data = DATA_PTR(self);
  uint32_t action;
  int syscall;
  int rc;
  mrb_int _action, _syscall;
  mrb_value args; // Array

  mrb_get_args(mrb, "iiA", &_action, &_syscall, &args);
  action = (uint32_t)_action;
  syscall = (int)_syscall;
  int len = RARRAY_LEN(args);

  switch(len) {
  case 0:
    rc = seccomp_rule_add(data->ctx, action, syscall, 0);
    break;
  case 1:
    rc = seccomp_rule_add(data->ctx, action, syscall, 1,
                          MRB_SECCOMP_CMP_FIND(args, 0));
    break;
  case 2:
    rc = seccomp_rule_add(data->ctx, action, syscall, 2,
                          MRB_SECCOMP_CMP_FIND(args, 0), MRB_SECCOMP_CMP_FIND(args, 1));
    break;
  case 3:
    rc = seccomp_rule_add(data->ctx, action, syscall, 3,
                          MRB_SECCOMP_CMP_FIND(args, 0), MRB_SECCOMP_CMP_FIND(args, 1), MRB_SECCOMP_CMP_FIND(args, 2));
    break;
  case 4:
    rc = seccomp_rule_add(data->ctx, action, syscall, 4,
                          MRB_SECCOMP_CMP_FIND(args, 0), MRB_SECCOMP_CMP_FIND(args, 1), MRB_SECCOMP_CMP_FIND(args, 2), MRB_SECCOMP_CMP_FIND(args, 3));
    break;
  case 5:
    rc = seccomp_rule_add(data->ctx, action, syscall, 5,
                          MRB_SECCOMP_CMP_FIND(args, 0), MRB_SECCOMP_CMP_FIND(args, 1), MRB_SECCOMP_CMP_FIND(args, 2), MRB_SECCOMP_CMP_FIND(args, 3), MRB_SECCOMP_CMP_FIND(args, 4));
    break;
  case 6:
    rc = seccomp_rule_add(data->ctx, action, syscall, 6,
                          MRB_SECCOMP_CMP_FIND(args, 0), MRB_SECCOMP_CMP_FIND(args, 1), MRB_SECCOMP_CMP_FIND(args, 2), MRB_SECCOMP_CMP_FIND(args, 3), MRB_SECCOMP_CMP_FIND(args, 4), MRB_SECCOMP_CMP_FIND(args, 5));
    break;
  default:
    mrb_raise(mrb, E_ARGUMENT_ERROR, "Arg size exceeded to pass to seccomp_rule_add");
    rc = -1;
    break;
  }
  if(rc < 0) {
#ifdef MRB_DEBUG
    perror("seccomp_rule_add");
#endif
    mrb_sys_fail(mrb, "seccomp_rule_add failed");
  }
  return mrb_fixnum_value(rc);
}

#define MRB_SECCOMP_EXPORT_CONST(c) mrb_define_const(mrb, parent, #c, mrb_fixnum_value(c))

void mrb_mruby_seccomp_gem_init(mrb_state *mrb)
{
  struct RClass *parent, *context, *arg_cmp;
    parent = mrb_define_module(mrb, "Seccomp");
    mrb_define_module_function(mrb, parent, "__gen_syscall_table", mrb_seccomp_generate_syscall_table, MRB_ARGS_NONE());

    context = mrb_define_class_under(mrb, parent, "Context", mrb->object_class);
    mrb_define_method(mrb, context, "initialize", mrb_seccomp_init, MRB_ARGS_REQ(1));
    mrb_define_method(mrb, context, "__add_rule", mrb_seccomp_add_rule, MRB_ARGS_REQ(3));
    /* mrb_define_method(mrb, seccomp, "hello", mrb_seccomp_hello, MRB_ARGS_NONE()); */
    /* mrb_define_class_method(mrb, seccomp, "hi", mrb_seccomp_hi, MRB_ARGS_NONE()); */

    arg_cmp = mrb_define_class_under(mrb, parent, "ArgOperator", mrb->object_class);
    mrb_define_method(mrb, arg_cmp, "initialize", mrb_seccomp_arg_cmp_init, MRB_ARGS_ARG(3,4));

    MRB_SECCOMP_EXPORT_CONST(SCMP_ACT_ALLOW);
    MRB_SECCOMP_EXPORT_CONST(SCMP_ACT_TRAP);
    MRB_SECCOMP_EXPORT_CONST(SCMP_ACT_KILL);

    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_EQ);
    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_NE);
    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_GE);
    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_GT);
    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_LE);
    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_LT);
    MRB_SECCOMP_EXPORT_CONST(SCMP_CMP_MASKED_EQ);
    DONE;
}

void mrb_mruby_seccomp_gem_final(mrb_state *mrb)
{
}
