MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'

  conf.gem mgem: 'mruby-process'
  conf.gem mgem: 'mruby-uname'
  conf.gem github: 'haconiwa/mruby-exec'

  conf.gem '../mruby-seccomp'
  conf.enable_debug
  conf.enable_test

  if ENV['USE_HEAD']
    conf.cc.defines << 'MRB_SECCOMP_USE_HEAD_LIB'
  end
end
