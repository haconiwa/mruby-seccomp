MRUBY_CONFIG=File.expand_path(ENV["MRUBY_CONFIG"] || "ci_build_config.rb")
MRUBY_VERSION=ENV["MRUBY_VERSION"] || "2.1.2"
v = ENV["DEBUG"] ? "-v" : ""

file :mruby do
  cmd =  "git clone --depth=1 git://github.com/mruby/mruby.git"
  if MRUBY_VERSION != 'master'
    cmd << " && cd mruby"
    cmd << " && git fetch --tags && git checkout $(git rev-parse #{MRUBY_VERSION})"
  end
  sh cmd
end

desc "gen syscall table src"
task :syscall_table do
  sh "ruby src/gen_syscall_table.rb"
end

desc "compile binary"
task :compile => :mruby do
  sh "cd mruby && MRUBY_CONFIG=#{MRUBY_CONFIG} rake all #{v}"
end

desc "test"
task :test => :mruby do
  sh "cd mruby && MRUBY_CONFIG=#{MRUBY_CONFIG} rake all test #{v}"
end

desc "cleanup"
task :clean do
  exit 0 unless File.directory?('mruby')
  sh "cd mruby && rake deep_clean"
end

desc "memleak test"
task :memtest => :compile do
  sh "valgrind --leak-check=full ./mruby/bin/mruby -e '100.times { c = Seccomp.new(default: :allow); c.kill(:mkdir, Seccomp::ARG(:>=, 0), Seccomp::ARG(:>=, 0)); c.load }'"
end

task :default => :compile
