context = Seccomp.new(default: :allow) do |rule|
  rule.kill(:mkdir, Seccomp::ARG(:>=, 0), Seccomp::ARG(:>=, 0))
end
context.load

exec "/bin/bash"
# And then try to mkdir
