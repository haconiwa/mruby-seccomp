##
## Seccomp Test
##

assert("Seccomp::Context.new") do
  ctx = Seccomp::Context.new Seccomp::SCMP_ACT_KILL
  assert_true(ctx.is_a? Seccomp::Context)
end
