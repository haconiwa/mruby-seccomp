module Seccomp
  class << self
    def __syscall__table
      @__syscall__table ||= __gen_syscall_table
    end

    def syscall_to_i(name)
      __syscall__table[name.to_s]
    end

    def syscall_to_tupple(i)
      __syscall__table.find{|p| p[1] == i }
    end

    def syscall_to_name(i)
      syscall_to_tupple(i)[0]
    end

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
      return syscall_to_i(syscall)
    end

    def new(options={})
      def_action = options[:default]
      unless def_action
        raise ArgumentError, "Please specify default action by `default: ...'"
      end

      ctx = Context.new(to_action(def_action))
      yield(ctx) if block_given?

      return ctx
    end
  end
end
