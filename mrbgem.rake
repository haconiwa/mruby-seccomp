require 'open3'
require 'fileutils'
$LOAD_PATH << File.expand_path('../mrblib', __FILE__)

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

  def spec.bundle_seccomp(is_build_head)
    version = is_build_head ? "master" : Seccomp::LIBSECCOMP_VERSION

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
        unless is_build_head
          run_command ENV, "curl -L https://github.com/seccomp/libseccomp/releases/download/v#{version}/libseccomp-#{version}.tar.gz | tar -xz -f - -C #{tmpdir}"
        else
          run_command ENV, "git clone --depth=1 https://github.com/seccomp/libseccomp.git #{tmpdir}/libseccomp-#{version}"
        end
        run_command ENV, "mv -f #{tmpdir}/libseccomp-#{version} #{seccomp_dir(build)}"
      end
    end

    file libseccomp_a(build) => seccomp_header(build) do
      sh "mkdir -p #{seccomp_objs_dir(build)}"
      Dir.chdir seccomp_dir(build) do
        unless File.exist? "./configure"
          run_command ENV, "./autogen.sh"
        end
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

  spec.bundle_seccomp(spec.build.cc.defines.flatten.include?("MRB_SECCOMP_USE_HEAD_LIB"))

  spec.add_test_dependency 'mruby-print'
  spec.add_test_dependency 'mruby-io',      mgem: 'mruby-io'
  spec.add_test_dependency 'mruby-process', mgem: 'mruby-process'
  spec.add_test_dependency 'mruby-uname',   mgem: 'mruby-uname'
  spec.add_test_dependency 'mruby-exec',    github: 'haconiwa/mruby-exec'
end
