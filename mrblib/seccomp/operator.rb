module Seccomp
  def self.ARG(op, arg1, arg2=nil)
    RawOp.new(op, arg1, arg2)
  end

  class RawOp
    def initialize(op, arg1, arg2)
      @op = op
      @arg1 = arg1
      @arg2 = arg2
    end

    def to_real_operator(index)
      op_enum = get_op_enum
      if @arg2
        ArgOperator.new(index, op_enum, @arg1, @arg2)
      else
        ArgOperator.new(index, op_enum, @arg1)
      end
    end

    private
    def get_op_enum
      return @op if @op.is_a?(Integer)
      case @op.to_sym
      when :==, :eq, :SCMP_CMP_EQ
        Seccomp::SCMP_CMP_EQ
      when :!=, :ne, :SCMP_CMP_NE
        Seccomp::SCMP_CMP_NE
      when :<,  :lt, :SCMP_CMP_LT
        Seccomp::SCMP_CMP_LT
      when :<=, :le, :SCMP_CMP_LE
        Seccomp::SCMP_CMP_LE
      when :>,  :gt, :SCMP_CMP_GT
        Seccomp::SCMP_CMP_GT
      when :>=, :ge, :SCMP_CMP_GE
        Seccomp::SCMP_CMP_GE
      when :=~, :masqed_eq, :SCMP_CMP_MASKED_EQ
        Seccomp::SCMP_CMP_MASKED_EQ
      else
        raise("Invalid op expression: #{@op}")
      end
    end
  end
end
