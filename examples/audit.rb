# To watch audit logs,
# run `sudo tail -f /var/log/syslog` in background.
#
# Will get somethng loke:
# Dec  4 12:16:27 ubuntu2004 kernel: [ 7961.935178] audit: type=1326 audit(1607084187.939:48): gauid=1000 uid=1000 gid=1000 ses=4 subj=unconfined pid=11867 comm="mkdir" exe="/usr/bin/mkdir" sig=0 arch=c000003e syscall=83 compat=0 ip=0x7f4fc7256dcb code=0x7ffc0000
# Dec  4 12:16:27 ubuntu2004 kernel: [ 7961.937344] audit: type=1326 audit(1607084187.939:49): auid=1000 uid=1000 gid=1000 ses=4 subj=unconfined pid=11869 comm="mkdir" exe="/usr/bin/mkdir" sig=0 arch=c000003e syscall=83 compat=0 ip=0x7f9ab3595dcb code=0x7ffc0000
# Dec  4 12:16:27 ubuntu2004 kernel: [ 7961.939478] audit: type=1326 audit(1607084187.943:50): auid=1000 uid=1000 gid=1000 ses=4 subj=unconfined pid=11871 comm="mkdir" exe="/usr/bin/mkdir" sig=0 arch=c000003e syscall=83 compat=0 ip=0x7ff72e6f7dcb code=0x7ffc0000
# Dec  4 12:16:27 ubuntu2004 kernel: [ 7961.941049] audit: type=1326 audit(1607084187.943:51): auid=1000 uid=1000 gid=1000 ses=4 subj=unconfined pid=11873 comm="rmdir" exe="/usr/bin/rmdir" sig=0 arch=c000003e syscall=84 compat=0 ip=0x7ff6251aee9b code=0x7ffc0000
# Dec  4 12:16:27 ubuntu2004 kernel: [ 7961.942467] audit: type=1326 audit(1607084187.943:52): auid=1000 uid=1000 gid=1000 ses=4 subj=unconfined pid=11875 comm="rmdir" exe="/usr/bin/rmdir" sig=0 arch=c000003e syscall=84 compat=0 ip=0x7fae52b29e9b code=0x7ffc0000
# Dec  4 12:16:27 ubuntu2004 kernel: [ 7961.943977] audit: type=1326 audit(1607084187.947:53): auid=1000 uid=1000 gid=1000 ses=4 subj=unconfined pid=11877 comm="rmdir" exe="/usr/bin/rmdir" sig=0 arch=c000003e syscall=84 compat=0 ip=0x7f9f42fd7e9b code=0x7ffc0000
#

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
