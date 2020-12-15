uds_path = ENV['TRACER_UDS_PATH'] || "/tmp/tracer.sock"
if ARGV[0] == '--'
  ARGV.shift
end

argv = if ARGV.empty?
         ["/usr/bin/ruby", "-run", "-e", "httpd", "--", "/var/www/html"]
       else
         ARGV.dup
       end

context = Seccomp.new(default: :allow) do |rule|
  rule.notify(:kill, Seccomp::ARG(:>=, 0), Seccomp::ARG(:==, 60))
end
context.load
nfd = context.notify_fd

uds = UNIXSocket.open(uds_path)
Seccomp.sendfd(uds.fileno, nfd)
uds.close
IO.for_fd(nfd)

puts "Invoking"

Exec.execve(
  ENV.to_hash.merge("LD_PRELOAD" => "libcakehole_listen.so"),
  *argv
)
