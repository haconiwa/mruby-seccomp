uds_path = ARGV.shift
ARGV.shift if ARGV[0] == '--'
args = ARGV.dup

pid = fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.notify(:listen)
  end
  context.load
  p nfd = context.notify_fd

  uds = UNIXSocket.open(uds_path)
  Seccomp.sendfd(uds.fileno, nfd)
  uds.close
  IO.for_fd(nfd)

  puts "Invoking: #{args.inspect}"
  Exec.exec(*args)
end

p Process.waitpid2(pid)
