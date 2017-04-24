pid = Process.fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.trace(:getuid, 0)
    rule.trace(:uname, 0)
  end
  context.load

  # uname will be called 4 times: 1 in bash, 3 in uname(1)
  exec '/bin/bash', '-c', 'exec uname -a'
end

ret = Seccomp.start_trace(pid) do |syscall, ud|
  name = Seccomp.syscall_to_name(syscall)
  puts "[#{pid}]: syscall #{name}(##{syscall}) called. (ud: #{ud})"
end

p(ret)
