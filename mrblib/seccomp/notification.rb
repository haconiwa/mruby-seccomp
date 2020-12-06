module Seccomp
  class Notification
    attr_accessor :pid, :notify_fd, :raw_args,
                  :retval, :reterror,
                  :continue

    def respond(&b)
      respond_internal(&b)
    end
  end
end
