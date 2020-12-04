##
## Seccomp Test
##

def redirect_stdout(fpath)
  MRubySeccmopTestUtil.dup2 File.open(fpath, 'w').fileno, 1
end

def redirect_stderr(fpath)
  MRubySeccmopTestUtil.dup2 File.open(fpath, 'w').fileno, 2
end

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
    redirect_stderr '/dev/null'
    exec "/usr/bin/env", "uname", "-a"
  end
  pid, ret = Process.waitpid2(pid)

  assert_true(ret.signaled?)
  assert_equal(ret.termsig, 31) # SYGSIS in Linux
end

if Seccomp.const_defined?(:SCMP_ACT_LOG)
  assert("Seccomp::Context#audit") do
    ctx = Seccomp.new(default: :allow) do |rule|
      rule.log(:uname)
    end

    pid = Process.fork do
      ctx.load
      redirect_stdout '/dev/null'
      exec "/usr/bin/env", "uname", "-a"
    end
    pid, ret = Process.waitpid2(pid)

    assert_true(ret.exited?)
    assert_equal(0, ret.exitstatus, "SCMP_ACT_LOG occurs no error")
  end
end

assert("Seccomp::Context#errno") do
  errno = Errno::EBUSY.new.errno

  ctx = Seccomp.new(default: :allow) do |rule|
    rule.errno(errno, :uname)
  end

  errfile = "/tmp/#{$$}.err"
  pid = Process.fork do
    ctx.load
    redirect_stdout '/dev/null'
    redirect_stderr errfile
    exec "/usr/bin/env", "uname", "-a"
  end
  pid, ret = Process.waitpid2(pid)

  assert_true(ret.exited?)
  assert_equal(1, ret.exitstatus, "SCMP_ACT_ERRNO occurs normal error")

  f = File.open(errfile).read(2048)
  assert_true(f.include?("Device or resource busy"), "Includes 'Device or resource busy'")

  system "rm -f #{errfile}"
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
  assert_true ret.exited?
  assert_true $?.exited?
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
  assert_true ret.exited?
  assert_true $?.exited?
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
  assert_false ret.exited?
  assert_false $?.exited?
  assert_equal 1, count
end
