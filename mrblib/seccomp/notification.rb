module Seccomp
  class Notification
    attr_accessor :pid, :notify_fd, :raw_args,
                  :retval, :reterror

    def respond(&b)
      respond_internal(&b)
    end
  end
end
