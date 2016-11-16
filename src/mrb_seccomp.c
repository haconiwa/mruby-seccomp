/*
** mrb_seccomp.c - Seccomp class
**
** Copyright (c) Uchio Kondo 2016
**
** See Copyright Notice in LICENSE
*/

#include <mruby.h>
#include <mruby/data.h>
#include <seccomp.h>

#include "mrb_seccomp.h"

#define DONE mrb_gc_arena_restore(mrb, 0);

typedef struct {
  scmp_filter_ctx ctx;
  uint32_t def_action;
} mrb_seccomp_data;

static void mrb_seccomp_free(mrb_state *mrb, void *p) {
  mrb_seccomp_data *data = (mrb_seccomp_data*)p;
  seccomp_release(data->ctx);
  mrb_free(mrb, data);
}

static const struct mrb_data_type mrb_seccomp_data_type = {
  "mrb_seccomp_data", mrb_seccomp_free,
};

static mrb_value mrb_seccomp_init(mrb_state *mrb, mrb_value self)
{
  mrb_seccomp_data *data;
  mrb_int def_action;

  data = (mrb_seccomp_data *)DATA_PTR(self);
  if (data) {
    mrb_seccomp_free(mrb, data);
  }
  DATA_TYPE(self) = &mrb_seccomp_data_type;
  DATA_PTR(self) = NULL;

  mrb_get_args(mrb, "i", &def_action);
  data = (mrb_seccomp_data *)mrb_malloc(mrb, sizeof(mrb_seccomp_data));
  data->ctx = seccomp_init((uint32_t)def_action);
  data->def_action = (uint32_t)def_action;
  DATA_PTR(self) = data;

  return self;
}

/* static mrb_value mrb_seccomp_hello(mrb_state *mrb, mrb_value self) */
/* { */
/*   mrb_seccomp_data *data = DATA_PTR(self); */

/*   return mrb_str_new(mrb, data->str, data->len); */
/* } */

#define MRB_SECCOMP_EXPORT_CONST(c) mrb_define_const(mrb, parent, #c, mrb_fixnum_value(c))

void mrb_mruby_seccomp_gem_init(mrb_state *mrb)
{
  struct RClass *parent, *context;
    parent = mrb_define_module(mrb, "Seccomp");
    context = mrb_define_class_under(mrb, parent, "Context", mrb->object_class);
    mrb_define_method(mrb, context, "initialize", mrb_seccomp_init, MRB_ARGS_REQ(1));
    /* mrb_define_method(mrb, seccomp, "hello", mrb_seccomp_hello, MRB_ARGS_NONE()); */
    /* mrb_define_class_method(mrb, seccomp, "hi", mrb_seccomp_hi, MRB_ARGS_NONE()); */

    MRB_SECCOMP_EXPORT_CONST(SCMP_ACT_ALLOW);
    MRB_SECCOMP_EXPORT_CONST(SCMP_ACT_TRAP);
    MRB_SECCOMP_EXPORT_CONST(SCMP_ACT_KILL);
    DONE;
}

void mrb_mruby_seccomp_gem_final(mrb_state *mrb)
{
}
