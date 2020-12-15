uds_path = ARGV.shift || "/tmp/tracer.sock"
system "rm -f #{uds_path}"
serv = UNIXServer.new(uds_path)
puts "Socket: #{uds_path}"

loop do
  sock = serv.accept
  puts "Invoker process connected!"

  nfd = Seccomp.recvfd(sock.fileno)

  notif = Seccomp::Notification.new(nfd)
  notif.respond do |n|
    print "Received kill(2) invocation from PID = #{n.pid}\n" +
          "You can 1) make CRIU image 2) continue process 3) abort process: "
    res = gets.chomp

    if res == "1"
      if system "mhctl service dump -t #{n.pid}"
        puts "Dump OK!"
        exit
      else
        raise "Dump is failed"
      end
    elsif res == "2"
      puts "Continue."
      #n.continue = true
      n.retval = 0
    else
      n.retval = -1
      n.reterror = -999 # TODO: specified retcode in cakehole
    end
  end

  sock.close
  IO.for_fd(nfd).close
end
