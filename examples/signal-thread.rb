pid = Process.fork do
  SignalThread.trap(:SIGSYS, detailed: true) do |info|
    puts "SigInfo: #{info.inspect}"
    puts "Trapped: syscall #{Seccomp.syscall_to_name(info.syscall)} = ##{info.syscall}"
  end
  context = Seccomp.new(default: :allow) do |rule|
    rule.trap(:uname)
  end
  context.load

  begin
    # Then hit `uname`
    p "nodename: " + Uname.nodename
  rescue => e
    puts "Catch as error: " + e.message
    puts "Trapping is OK"
  end
end

p(Process.waitpid2 pid)
