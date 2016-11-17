pid = Process.fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.kill(:uname)
  end
  context.load

  # Then hit `uname`
  exec "/usr/bin/uname", "-a"
end

p(Process.waitpid2 pid)
