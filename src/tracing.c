/*
** tracing.c - Seccomp wrapper around syscall tracing
**
** Copyright (c) Uchio Kondo 2016
**
** See Copyright Notice in LICENSE
*/

#include "mrb_seccomp.h"

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

void mrb_mruby_seccomp_tracing_init(mrb_state *mrb, struct RClass *parent) {
  struct RClass *tracer =
      mrb_define_class_under(mrb, parent, "Tracer", mrb->object_class);
  MRB_SET_INSTANCE_TT(tracer, MRB_TT_DATA);
  mrb_define_method(mrb, tracer, "initialize", mrb_seccomp_tracer_init,
                    MRB_ARGS_REQ(1));
}
