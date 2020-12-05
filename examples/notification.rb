tracer, tracee = Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM, 0)

p1 = fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.notify(:mkdir)
  end
  context.load
  p context.notify_fd
end

p Process.waitpid2(p1)
