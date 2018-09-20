pid = Process.fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.trace(:getuid, 0)
    rule.trace(:uname, 0)
  end
  context.load

  # uname will be called 10 times: 1 in bash, 3 * 3 in uname(1)
  exec '/bin/bash', '-c', 'uname -a; uname -a; uname -a'
  #exec '/bin/bash', '-c', 'exec uname -a'
  #exec '/bin/bash', '-l'
end

p $?.inspect
ret = Seccomp.start_trace(pid) do |syscall, _pid, ud|
  name = Seccomp.syscall_to_name(syscall)
  puts "[#{_pid}]: syscall #{name}(##{syscall}) called. (ud: #{ud})"
end

p $?.exited?
