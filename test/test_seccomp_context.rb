##
## Seccomp Test
##

assert("Seccomp::Context.new") do
  ctx = Seccomp::Context.new Seccomp::SCMP_ACT_KILL
  assert_true(ctx.is_a? Seccomp::Context)
end

assert("Seccomp::Context#kill") do
  ctx = Seccomp.new(default: :allow) do |rule|
    rule.kill(:uname)
  end

  pid = Process.fork do
    ctx.load
    exec "/usr/bin/env", "uname", "-a"
  end
  pid, ret = Process.waitpid2(pid)

  assert_true(ret.signaled?)
  assert_equal(ret.termsig, 31) # SYGSIS in Linux
end

assert("Seccomp::Context.new") do
  ctx = Seccomp::Context.new Seccomp::SCMP_ACT_KILL
  assert_true(ctx.is_a? Seccomp::Context)
end

assert("Seccomp.start_trace") do
  pid = Process.fork do
    ctx = Seccomp.new(default: :allow) do |rule|
      rule.trace(:uname, 0)
    end
    ctx.load
    exec '/bin/bash', '-c', 'exec uname -a >/dev/null'
  end

  count = 0
  ret = Seccomp.start_trace(pid) do |syscall, ud|
    count += 1
  end

  assert_equal "exited", ret
  assert_equal 4, count
end

assert("Seccomp.start_trace with forking processes") do
  pid = Process.fork do
    ctx = Seccomp.new(default: :allow) do |rule|
      rule.trace(:uname, 0)
    end
    ctx.load
    exec '/bin/bash', '-c', 'for i in 1 2 3; do uname -a >/dev/null ; done'
  end

  count = 0
  ret = Seccomp.start_trace(pid) do |syscall, ud|
    count += 1
  end

  assert_equal "exited", ret
  assert_equal 10, count
end

assert("Seccomp.start_trace_detach") do
  pid = Process.fork do
    ctx = Seccomp.new(default: :allow) do |rule|
      rule.trace(:uname, 0)
    end
    ctx.load
    exec '/bin/bash', '-c', 'exec uname -a >/dev/null'
  end

  count = 0
  ret = Seccomp.start_trace_detach(pid) do |syscall, ud|
    count += 1
  end
  assert_not_equal "exited", ret
  assert_equal 1, count
end
