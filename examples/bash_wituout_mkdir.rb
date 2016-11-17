context = Seccomp.new(default: :allow) do |rule|
  rule.kill(:mkdir, Seccomp::ARG(:>=, 0), Seccomp::ARG(:>=, 0))
end

pid = Process.fork do
  context.load

  puts "==== It will be jailed. Please try to mkdir"
  exec "/bin/sh"
end

p(Process.waitpid2 pid)

puts "==== It will not be jailed"
exec "/bin/sh"
