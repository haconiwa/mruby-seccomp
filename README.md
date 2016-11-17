# mruby-seccomp   [![Build Status](https://travis-ci.org/haconiwa/mruby-seccomp.svg?branch=master)](https://travis-ci.org/haconiwa/mruby-seccomp)

A mruby gem to access libseccomp API

## install by mrbgems

- add conf.gem line to `build_config.rb`

```ruby
MRuby::Build.new do |conf|

  # ... (snip) ...

  conf.gem :github => 'haconiwa/mruby-seccomp'
end
```

## example

```ruby
context = Seccomp.new(default: :kill) do |rule|
  rule.allow(:open)
  rule.allow(:close)
  rule.allow(:read, Seccomp::ARG(:==, $stdin.fileno), Seccomp::ARG(:!=, 0x0), Seccomp::ARG(:<=, File::SSIZE_MAX))
  # rule.kill(:open)
  # rule.trap(:open) ...
end
context.allow(...) # if necessary out of block

context.load # to load context to current process
context.reset(:allow) # to reset

Process.fork do
  # This process is also jailed
  ...
end
```

## License

`mruby-seccomp` itself is under the MIT License:

- see LICENSE file

## TODO

* [ ] Trapping SIGSYS and get `si_syscall` in the block
