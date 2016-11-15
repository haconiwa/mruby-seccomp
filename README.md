# mruby-seccomp   [![Build Status](https://travis-ci.org/haconiwa/mruby-seccomp.svg?branch=master)](https://travis-ci.org/haconiwa/mruby-seccomp)
Seccomp class
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
p Seccomp.hi
#=> "hi!!"
t = Seccomp.new "hello"
p t.hello
#=> "hello"
p t.bye
#=> "hello bye"
```

## License
under the MIT License:
- see LICENSE file
