# To watch audit logs,
# run `sudo tail -f /var/log/syslog` in background.

pid = Process.fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.log(:mkdir)
    rule.log(:rmdir)

    rule.kill(:uname)
  end
  context.load

  system '/usr/bin/mkdir /tmp/sample1'
  system '/usr/bin/mkdir /tmp/sample2'
  system '/usr/bin/mkdir /tmp/sample3'

  system '/usr/bin/rmdir /tmp/sample1'
  system '/usr/bin/rmdir /tmp/sample2'
  system '/usr/bin/rmdir /tmp/sample3'

  sleep 3
  # Also kill uname
  system '/usr/bin/uname', '-a'
  exit
end

p(Process.waitpid2 pid)
