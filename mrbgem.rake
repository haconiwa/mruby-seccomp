MRuby::Gem::Specification.new('mruby-seccomp') do |spec|
  spec.license = 'MIT'
  spec.authors = 'Uchio Kondo'

  def spec.bundle_seccomp
    version = '2.3.1'

    def seccomp_dir(b); "#{b.build_dir}/vendor/argtable3"; end
    def seccomp_objs_dir(b); "#{seccomp_dir(b)}/.objs"; end
    def seccomp_header(b); "#{seccomp_dir(b)}/include/seccomp.h"; end
    def libseccomp_a(b); libfile "#{seccomp_objs_dir(b)}/lib/libseccomp"; end

    task :clean do
      FileUtils.rm_rf [seccomp_dir(build)]
    end

    file seccomp_header(build) do
      unless File.exist? seccomp_dir(build)
        tmpdir = '/tmp'
        sh "rm -rf #{tmpdir}/libseccomp-#{version}"
        sh "mkdir -p #{File.dirname(seccomp_dir(build))}"
        sh "curl -L https://github.com/seccomp/libseccomp/releases/download/v#{version}/libseccomp-#{version}.tar.gz | tar -xz -f - -C #{tmpdir}"
        sh "mv -f #{tmpdir}/libseccomp-#{version} #{seccomp_dir(build)}"
      end
    end

    file libseccomp_a(build) => seccomp_header(build) do
      sh "mkdir -p #{seccomp_objs_dir(build)}"
      Dir.chdir seccomp_dir(build) do
        sh "./configure --enable-static --prefix=#{seccomp_objs_dir(build)}"
        sh "make"
        sh "make install"
      end
    end

    libmruby_a = libfile("#{build.build_dir}/lib/libmruby")
    file libmruby_a => libseccomp_a(build)

    self.cc.include_paths << File.dirname(seccomp_header(build))
    self.linker.library_paths << File.dirname(libseccomp_a(build))
    self.linker.libraries << 'seccomp'
  end

  spec.bundle_seccomp
end
