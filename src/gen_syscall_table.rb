TEMPLATE = <<EOC
#include <mruby.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/hash.h>
#include <seccomp.h>

#define MRB_SECCOMP_SET_SYSCALL(s)                                      \
  mrb_hash_set(mrb, table, mrb_str_new_lit(mrb, #s), mrb_fixnum_value(SCMP_SYS(s)))

mrb_value mrb_seccomp_generate_syscall_table(mrb_state *mrb, mrb_value self)
{
  mrb_value table = mrb_hash_new(mrb);
<% @syscalls.each do |syscall| %>
#ifdef __NR_<%= syscall %>
  MRB_SECCOMP_SET_SYSCALL(<%= syscall %>);
#endif
<% end %>

  return table;
}
EOC

require 'erb'
open(File.expand_path('../syscall_table.c', __FILE__), 'w') do |f|
  @syscalls = `ausyscall --dump | awk '{print $2}'`.split.map{|l| l.chomp }.delete_if{|l| l.empty? }
  f.write ERB.new(TEMPLATE).result(binding)
end
