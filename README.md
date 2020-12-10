# mruby-seccomp [![Build Status](https://github.com/haconiwa/mruby-seccomp/workflows/Testing/badge.svg)](https://github.com/haconiwa/mruby-seccomp/actions?query=workflow%3ATesting)

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


Process.fork do
  # This process is also jailed
  ...
end

context.fork do
  # This spawns a new process which is jailed
  # but the parent process will be remain unloaded
end

context.reset(:allow) # to reset
```

## License

`mruby-seccomp` itself is under the MIT License:

- see LICENSE file

## TODO

* [ ] Trapping SIGSYS and get `si_syscall` in the block
