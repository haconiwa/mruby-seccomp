##
## Seccomp Test
##

assert("Seccomp#hello") do
  t = Seccomp.new "hello"
  assert_equal("hello", t.hello)
end

assert("Seccomp#bye") do
  t = Seccomp.new "hello"
  assert_equal("hello bye", t.bye)
end

assert("Seccomp.hi") do
  assert_equal("hi!!", Seccomp.hi)
end
