pid = Process.fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.trap(:uname)
  end
  Seccomp.on_trap do |syscall|
    puts "Trapped: syscall #{Seccomp.syscall_to_name(syscall)} = ##{syscall}"
  end
  context.load

  # Then hit `uname`
  p "nodename: " + Uname.nodename
end

p(Process.waitpid2 pid)
