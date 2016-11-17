MRuby::Build.new do |conf|
  toolchain :gcc
  conf.gembox 'default'

  conf.gem mgem: 'mruby-process'
  conf.gem github: 'haconiwa/mruby-exec'

  conf.gem '../mruby-seccomp'
  conf.enable_test
end
