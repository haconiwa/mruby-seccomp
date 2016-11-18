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

assert("Seccomp.trap") do
  r, w = IO.pipe
  pid = Process.fork do
    r.close

    ctx = Seccomp.new(default: :allow) do |rule|
      rule.trap(:uname)
    end
    Seccomp.on_trap do |sc|
      data = Seccomp.syscall_to_tupple(sc)
      w.write data.inspect
      w.close
    end

    ctx.load
    begin
      "nodename: " + Uname.nodename
    rescue RuntimeError => e
      e
    end
  end
  w.close
  ret = r.read
  assert_equal('["uname", 63]', ret)

  Process.waitpid2(pid)
end
