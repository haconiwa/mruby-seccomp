/*
** mrb_seccomp.h - Seccomp class
**
** See Copyright Notice in LICENSE
*/

#ifndef MRB_SECCOMP_H
#define MRB_SECCOMP_H

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/error.h>
#include <mruby/variable.h>

#include <seccomp.h>
#include <signal.h>
#include <stdlib.h>

void mrb_mruby_seccomp_gem_init(mrb_state *mrb);

#endif
