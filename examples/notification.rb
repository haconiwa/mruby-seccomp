tracer, tracee = Socket.pair(Socket::AF_UNIX, Socket::SOCK_STREAM, 0)

p1 = fork do
  context = Seccomp.new(default: :allow) do |rule|
    rule.notify(:mkdir)
  end
  context.load
  p nfd = context.notify_fd
  Seccomp.sendfd(tracee, nfd)
  [nfd, tracer, tracee].each{|fd| IO.for_fd(fd).close }

  3.times do |i|
    begin
      Dir.mkdir "/tmp/foo-#{i}"
    rescue => e
      p e
    end
    sleep 1
  end

  system 'ls -l /tmp/ | grep foo && rmdir /tmp/foo-2'
  puts "Cleanup && Finish..."
end

p2 = fork do
  nfd = Seccomp.recvfd(tracer)
  # [tracer, tracee].each{|fd| IO.for_fd(fd).close }
  loop do
    notif = Seccomp::Notification.new(nfd)
    notif.respond do |n|
      addr = '0x%x' % n.raw_args[0]
      perm = '0%o' % n.raw_args[1]
      puts "Received: PID = #{n.pid}, ARGS = #{[addr, perm].inspect}"
      path = ""

      begin
        mem = File.open("/proc/#{n.pid}/mem", "r")
        mem.sysseek(n.raw_args[0])
        until path.include?("\0")
          path << mem.sysread(1024)
        end
        path = path.split("\0")[0]
        puts "calling: mkdir(#{path.inspect}, #{'%o' % n.raw_args[1]})"
      rescue Errno::EACCES => e
        puts "[!] Cannot open memory data. Skip"
      end

      if path == "/tmp/foo-2"
        puts "Do continue"
        n.continue = true
      else
        n.retval = -1
        n.reterror = -Errno::EBUSY.new.errno
      end
    end
  end
end
[tracer, tracee].each{|fd| IO.for_fd(fd).close }

p Process.waitpid2(p1)
p Process.waitpid2(p2)
