uds_path = ARGV.shift || "/tmp/seccomp-sock-#{$$}.sock"

serv = UNIXServer.new(uds_path)
puts "Socket: #{uds_path}"

loop do
  sock = serv.accept
  puts "Invoker process connected!"

  nfd = Seccomp.recvfd(sock.fileno)

  notif = Seccomp::Notification.new(nfd)
  notif.respond do |n|
    print "Received listen(2) invovation from PID = #{n.pid}. Are you going to allow startup? [y/N]: "
    res = gets.chomp

    if res == "y"
      puts "Accepted."
      n.continue = true
    else
      n.retval = -1
      n.reterror = -Errno::EPERM.new.errno
    end
  end

  sock.close
  IO.for_fd(nfd).close
end
