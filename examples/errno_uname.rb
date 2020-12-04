if !ARGV[0]
  puts "Usage: #{$0} ESYMBOL (e.g. ENOENT)"
  exit 1
end
errno = Errno.const_get(ARGV[0]).new.errno

pid = Process.fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.errno(errno, :uname)
  end
  context.load

  # Then hit `uname`
  exec "/usr/bin/uname", "-a"
end

p(Process.waitpid2 pid)
