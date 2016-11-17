module Seccomp
  class << self
    def __syscall__table
      @__syscall__table ||= __gen_syscall_table
    end

    def syscall_to_i(name)
      __syscall__table[name.to_s]
    end
  end
end
