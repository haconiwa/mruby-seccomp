module Seccomp
  class Context
    def add_rule(action, syscall, *args)
      new_args = []
      args.each_with_index do |a, i|
        new_args << a.to_real_operator(i)
      end
      __add_rule(Seccomp.to_action(action), Seccomp.to_syscall(syscall), new_args)
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

    def fork(wait=false, &blk)
      defined = begin Process; rescue NameError; false end
      unless defined
        raise "mruby-process is required to call this function"
      end

      ctx = self
      pid = Process.fork do
        ctx.load
        blk.call
      end
      if wait
        return Process.waitpid2(pid)
      else
        return pid
      end
    end
    alias jailed_fork fork
  end
end
