#include <mruby.h>
#include <mruby/error.h>
#include <unistd.h>

static mrb_value mrb_test_do_dup2(mrb_state *mrb, mrb_value self)
{
  mrb_int oldfd, newfd;
  mrb_get_args(mrb, "ii", &oldfd, &newfd);
  if(! dup2((int)oldfd, (int)newfd))
    mrb_sys_fail(mrb, "dup2");

  return mrb_nil_value();
}

void mrb_mruby_seccomp_gem_test(mrb_state *mrb)
{
  struct RClass *test = mrb_define_module(mrb, "MRubySeccmopTestUtil");
  mrb_define_module_function(mrb, test, "dup2", mrb_test_do_dup2, MRB_ARGS_REQ(2));
}
