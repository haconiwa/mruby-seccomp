MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'

  if ENV['MRB_SECCOMP_LIBVER']
    conf.cc.defines << "MRB_SECCOMP_LIBVER=#{ENV['MRB_SECCOMP_LIBVER']}"
  end
  conf.cc.flags << '-std=gnu99 -Wno-declaration-after-statement' 

  conf.gem mgem: 'mruby-process'
  conf.gem mgem: 'mruby-uname'
  conf.gem mgem: 'mruby-errno'
  conf.gem mgem: 'mruby-dir'
  conf.gem github: 'haconiwa/mruby-exec'

  conf.gem '../mruby-seccomp'
  conf.enable_debug
  conf.enable_test
end
