require 'open3'
require 'fileutils'
$LOAD_PATH << File.expand_path('../mrblib', __FILE__)

unless defined? DEFAULT_LIBSECCOMP_VERSION
  DEFAULT_LIBSECCOMP_VERSION = "2.3.1"
end

MRuby::Gem::Specification.new('mruby-seccomp') do |spec|
  require 'seccomp/versions'

  spec.license = 'MIT'
  spec.authors = 'Uchio Kondo'
  spec.version = Seccomp::VERSION

  def run_command env, command
    STDOUT.sync = true
    puts "EXEC\t[mruby-seccomp] #{command}"
    Open3.popen2e(env, command) do |stdin, stdout, thread|
      print stdout.read
      fail "#{command} failed" if thread.value != 0
    end
  end

  def spec.get_libseccomp_version
    if self.cc.defines.flatten.find{|d| d =~ /^MRB_SECCOMP_LIBVER=([\.0-9]+)$/ }
      return $1
    else
      DEFAULT_LIBSECCOMP_VERSION
    end
  end

  def spec.bundle_seccomp
    version = get_libseccomp_version

    def seccomp_dir(b); "#{b.build_dir}/vendor/libseccomp"; end
    def seccomp_objs_dir(b); "#{seccomp_dir(b)}/.objs"; end
    def seccomp_header(b); "#{seccomp_dir(b)}/include/seccomp.h"; end
    def libseccomp_a(b); libfile "#{seccomp_objs_dir(b)}/lib/libseccomp"; end

    task :clean do
      FileUtils.rm_rf [seccomp_dir(build)]
    end

    file seccomp_header(build) do
      unless File.exist? seccomp_dir(build)
        tmpdir = '/tmp'
        run_command ENV, "rm -rf #{tmpdir}/libseccomp-#{version}"
        run_command ENV, "mkdir -p #{File.dirname(seccomp_dir(build))}"
        run_command ENV, "curl -L https://github.com/seccomp/libseccomp/releases/download/v#{version}/libseccomp-#{version}.tar.gz | tar -xz -f - -C #{tmpdir}"
        run_command ENV, "mv -f #{tmpdir}/libseccomp-#{version} #{seccomp_dir(build)}"
      end
    end

    file libseccomp_a(build) => seccomp_header(build) do
      sh "mkdir -p #{seccomp_objs_dir(build)}"
      Dir.chdir seccomp_dir(build) do
        run_command ENV, "./configure --enable-static --disable-shared --prefix=#{seccomp_objs_dir(build)}"
        run_command ENV, "make"
        run_command ENV, "make install"
      end
    end

    libmruby_a = libfile("#{build.build_dir}/lib/libmruby")
    file libmruby_a => libseccomp_a(build)

    self.cc.include_paths << File.dirname(seccomp_header(build))
    self.linker.library_paths << File.dirname(libseccomp_a(build))
    self.linker.libraries << 'seccomp'
  end

  spec.bundle_seccomp

  spec.add_test_dependency 'mruby-print'
  spec.add_test_dependency 'mruby-io',      mgem: 'mruby-io'
  spec.add_test_dependency 'mruby-process', mgem: 'mruby-process'
  spec.add_test_dependency 'mruby-uname',   mgem: 'mruby-uname'
  spec.add_test_dependency 'mruby-errno',   mgem: 'mruby-errno'
  spec.add_test_dependency 'mruby-exec',    github: 'haconiwa/mruby-exec'
end
