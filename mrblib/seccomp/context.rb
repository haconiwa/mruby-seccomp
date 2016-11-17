module Seccomp
  class Context
    def add_rule(action, syscall, *args)
      new_args = []
      args.each_with_index do |a, i|
        new_args << a.to_real_operator(i)
      end
      __add_rule(to_action(action), to_syscall(syscall), new_args)
    end

    def allow(syscall, *args)
      add_rule(Seccomp::SCMP_ACT_ALLOW, syscall, *args)
    end

    def kill(syscall, *args)
      add_rule(Seccomp::SCMP_ACT_KILL, syscall, *args)
    end

    def trap(syscall, *args)
      add_rule(Seccomp::SCMP_ACT_TRAP, syscall, *args)
    end

    private
    def to_action(action)
      return action if action.is_a?(Integer)
      case action
      when :kill,  :SCMP_ACT_KILL
        Seccomp::SCMP_ACT_KILL
      when :trap,  :SCMP_ACT_TRAP
        Seccomp::SCMP_ACT_TRAP
      when :allow, :SCMP_ACT_ALLOW
        Seccomp::SCMP_ACT_ALLOW
      when :errno, :SCMP_ACT_ERRNO
        raise(NotImplementedAError, "Unsupported yet: #{action}")
      when :trace, :SCMP_ACT_TRACE
        raise(NotImplementedAError, "Unsupported yet: #{action}")
      else
        raise(ArgumentError, "Invalid action name: #{action}")
      end
    end

    def to_syscall(syscall)
      return syscall if syscall.is_a?(Integer)
      return Seccomp.syscall_to_i(syscall)
    end
  end
end
