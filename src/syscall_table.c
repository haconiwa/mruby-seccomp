#include <mruby.h>
#include <mruby/data.h>
#include <mruby/hash.h>
#include <mruby/string.h>
#include <seccomp.h>

#define MRB_SECCOMP_SET_SYSCALL(s) mrb_hash_set(mrb, table, mrb_str_new_lit(mrb, #s), mrb_fixnum_value(SCMP_SYS(s)))

mrb_value mrb_seccomp_generate_syscall_table(mrb_state *mrb, mrb_value self)
{
  mrb_value table = mrb_hash_new(mrb);

#ifdef __NR_x86_64
  MRB_SECCOMP_SET_SYSCALL(x86_64);
#endif

#ifdef __NR_read
  MRB_SECCOMP_SET_SYSCALL(read);
#endif

#ifdef __NR_write
  MRB_SECCOMP_SET_SYSCALL(write);
#endif

#ifdef __NR_open
  MRB_SECCOMP_SET_SYSCALL(open);
#endif

#ifdef __NR_close
  MRB_SECCOMP_SET_SYSCALL(close);
#endif

#ifdef __NR_stat
  MRB_SECCOMP_SET_SYSCALL(stat);
#endif

#ifdef __NR_fstat
  MRB_SECCOMP_SET_SYSCALL(fstat);
#endif

#ifdef __NR_lstat
  MRB_SECCOMP_SET_SYSCALL(lstat);
#endif

#ifdef __NR_poll
  MRB_SECCOMP_SET_SYSCALL(poll);
#endif

#ifdef __NR_lseek
  MRB_SECCOMP_SET_SYSCALL(lseek);
#endif

#ifdef __NR_mmap
  MRB_SECCOMP_SET_SYSCALL(mmap);
#endif

#ifdef __NR_mprotect
  MRB_SECCOMP_SET_SYSCALL(mprotect);
#endif

#ifdef __NR_munmap
  MRB_SECCOMP_SET_SYSCALL(munmap);
#endif

#ifdef __NR_brk
  MRB_SECCOMP_SET_SYSCALL(brk);
#endif

#ifdef __NR_rt_sigaction
  MRB_SECCOMP_SET_SYSCALL(rt_sigaction);
#endif

#ifdef __NR_rt_sigprocmask
  MRB_SECCOMP_SET_SYSCALL(rt_sigprocmask);
#endif

#ifdef __NR_rt_sigreturn
  MRB_SECCOMP_SET_SYSCALL(rt_sigreturn);
#endif

#ifdef __NR_ioctl
  MRB_SECCOMP_SET_SYSCALL(ioctl);
#endif

#ifdef __NR_pread
  MRB_SECCOMP_SET_SYSCALL(pread);
#endif

#ifdef __NR_pwrite
  MRB_SECCOMP_SET_SYSCALL(pwrite);
#endif

#ifdef __NR_readv
  MRB_SECCOMP_SET_SYSCALL(readv);
#endif

#ifdef __NR_writev
  MRB_SECCOMP_SET_SYSCALL(writev);
#endif

#ifdef __NR_access
  MRB_SECCOMP_SET_SYSCALL(access);
#endif

#ifdef __NR_pipe
  MRB_SECCOMP_SET_SYSCALL(pipe);
#endif

#ifdef __NR_select
  MRB_SECCOMP_SET_SYSCALL(select);
#endif

#ifdef __NR_sched_yield
  MRB_SECCOMP_SET_SYSCALL(sched_yield);
#endif

#ifdef __NR_mremap
  MRB_SECCOMP_SET_SYSCALL(mremap);
#endif

#ifdef __NR_msync
  MRB_SECCOMP_SET_SYSCALL(msync);
#endif

#ifdef __NR_mincore
  MRB_SECCOMP_SET_SYSCALL(mincore);
#endif

#ifdef __NR_madvise
  MRB_SECCOMP_SET_SYSCALL(madvise);
#endif

#ifdef __NR_shmget
  MRB_SECCOMP_SET_SYSCALL(shmget);
#endif

#ifdef __NR_shmat
  MRB_SECCOMP_SET_SYSCALL(shmat);
#endif

#ifdef __NR_shmctl
  MRB_SECCOMP_SET_SYSCALL(shmctl);
#endif

#ifdef __NR_dup
  MRB_SECCOMP_SET_SYSCALL(dup);
#endif

#ifdef __NR_dup2
  MRB_SECCOMP_SET_SYSCALL(dup2);
#endif

#ifdef __NR_pause
  MRB_SECCOMP_SET_SYSCALL(pause);
#endif

#ifdef __NR_nanosleep
  MRB_SECCOMP_SET_SYSCALL(nanosleep);
#endif

#ifdef __NR_getitimer
  MRB_SECCOMP_SET_SYSCALL(getitimer);
#endif

#ifdef __NR_alarm
  MRB_SECCOMP_SET_SYSCALL(alarm);
#endif

#ifdef __NR_setitimer
  MRB_SECCOMP_SET_SYSCALL(setitimer);
#endif

#ifdef __NR_getpid
  MRB_SECCOMP_SET_SYSCALL(getpid);
#endif

#ifdef __NR_sendfile
  MRB_SECCOMP_SET_SYSCALL(sendfile);
#endif

#ifdef __NR_socket
  MRB_SECCOMP_SET_SYSCALL(socket);
#endif

#ifdef __NR_connect
  MRB_SECCOMP_SET_SYSCALL(connect);
#endif

#ifdef __NR_accept
  MRB_SECCOMP_SET_SYSCALL(accept);
#endif

#ifdef __NR_sendto
  MRB_SECCOMP_SET_SYSCALL(sendto);
#endif

#ifdef __NR_recvfrom
  MRB_SECCOMP_SET_SYSCALL(recvfrom);
#endif

#ifdef __NR_sendmsg
  MRB_SECCOMP_SET_SYSCALL(sendmsg);
#endif

#ifdef __NR_recvmsg
  MRB_SECCOMP_SET_SYSCALL(recvmsg);
#endif

#ifdef __NR_shutdown
  MRB_SECCOMP_SET_SYSCALL(shutdown);
#endif

#ifdef __NR_bind
  MRB_SECCOMP_SET_SYSCALL(bind);
#endif

#ifdef __NR_listen
  MRB_SECCOMP_SET_SYSCALL(listen);
#endif

#ifdef __NR_getsockname
  MRB_SECCOMP_SET_SYSCALL(getsockname);
#endif

#ifdef __NR_getpeername
  MRB_SECCOMP_SET_SYSCALL(getpeername);
#endif

#ifdef __NR_socketpair
  MRB_SECCOMP_SET_SYSCALL(socketpair);
#endif

#ifdef __NR_setsockopt
  MRB_SECCOMP_SET_SYSCALL(setsockopt);
#endif

#ifdef __NR_getsockopt
  MRB_SECCOMP_SET_SYSCALL(getsockopt);
#endif

#ifdef __NR_clone
  MRB_SECCOMP_SET_SYSCALL(clone);
#endif

#ifdef __NR_fork
  MRB_SECCOMP_SET_SYSCALL(fork);
#endif

#ifdef __NR_vfork
  MRB_SECCOMP_SET_SYSCALL(vfork);
#endif

#ifdef __NR_execve
  MRB_SECCOMP_SET_SYSCALL(execve);
#endif

#ifdef __NR_exit
  MRB_SECCOMP_SET_SYSCALL(exit);
#endif

#ifdef __NR_wait4
  MRB_SECCOMP_SET_SYSCALL(wait4);
#endif

#ifdef __NR_kill
  MRB_SECCOMP_SET_SYSCALL(kill);
#endif

#ifdef __NR_uname
  MRB_SECCOMP_SET_SYSCALL(uname);
#endif

#ifdef __NR_semget
  MRB_SECCOMP_SET_SYSCALL(semget);
#endif

#ifdef __NR_semop
  MRB_SECCOMP_SET_SYSCALL(semop);
#endif

#ifdef __NR_semctl
  MRB_SECCOMP_SET_SYSCALL(semctl);
#endif

#ifdef __NR_shmdt
  MRB_SECCOMP_SET_SYSCALL(shmdt);
#endif

#ifdef __NR_msgget
  MRB_SECCOMP_SET_SYSCALL(msgget);
#endif

#ifdef __NR_msgsnd
  MRB_SECCOMP_SET_SYSCALL(msgsnd);
#endif

#ifdef __NR_msgrcv
  MRB_SECCOMP_SET_SYSCALL(msgrcv);
#endif

#ifdef __NR_msgctl
  MRB_SECCOMP_SET_SYSCALL(msgctl);
#endif

#ifdef __NR_fcntl
  MRB_SECCOMP_SET_SYSCALL(fcntl);
#endif

#ifdef __NR_flock
  MRB_SECCOMP_SET_SYSCALL(flock);
#endif

#ifdef __NR_fsync
  MRB_SECCOMP_SET_SYSCALL(fsync);
#endif

#ifdef __NR_fdatasync
  MRB_SECCOMP_SET_SYSCALL(fdatasync);
#endif

#ifdef __NR_truncate
  MRB_SECCOMP_SET_SYSCALL(truncate);
#endif

#ifdef __NR_ftruncate
  MRB_SECCOMP_SET_SYSCALL(ftruncate);
#endif

#ifdef __NR_getdents
  MRB_SECCOMP_SET_SYSCALL(getdents);
#endif

#ifdef __NR_getcwd
  MRB_SECCOMP_SET_SYSCALL(getcwd);
#endif

#ifdef __NR_chdir
  MRB_SECCOMP_SET_SYSCALL(chdir);
#endif

#ifdef __NR_fchdir
  MRB_SECCOMP_SET_SYSCALL(fchdir);
#endif

#ifdef __NR_rename
  MRB_SECCOMP_SET_SYSCALL(rename);
#endif

#ifdef __NR_mkdir
  MRB_SECCOMP_SET_SYSCALL(mkdir);
#endif

#ifdef __NR_rmdir
  MRB_SECCOMP_SET_SYSCALL(rmdir);
#endif

#ifdef __NR_creat
  MRB_SECCOMP_SET_SYSCALL(creat);
#endif

#ifdef __NR_link
  MRB_SECCOMP_SET_SYSCALL(link);
#endif

#ifdef __NR_unlink
  MRB_SECCOMP_SET_SYSCALL(unlink);
#endif

#ifdef __NR_symlink
  MRB_SECCOMP_SET_SYSCALL(symlink);
#endif

#ifdef __NR_readlink
  MRB_SECCOMP_SET_SYSCALL(readlink);
#endif

#ifdef __NR_chmod
  MRB_SECCOMP_SET_SYSCALL(chmod);
#endif

#ifdef __NR_fchmod
  MRB_SECCOMP_SET_SYSCALL(fchmod);
#endif

#ifdef __NR_chown
  MRB_SECCOMP_SET_SYSCALL(chown);
#endif

#ifdef __NR_fchown
  MRB_SECCOMP_SET_SYSCALL(fchown);
#endif

#ifdef __NR_lchown
  MRB_SECCOMP_SET_SYSCALL(lchown);
#endif

#ifdef __NR_umask
  MRB_SECCOMP_SET_SYSCALL(umask);
#endif

#ifdef __NR_gettimeofday
  MRB_SECCOMP_SET_SYSCALL(gettimeofday);
#endif

#ifdef __NR_getrlimit
  MRB_SECCOMP_SET_SYSCALL(getrlimit);
#endif

#ifdef __NR_getrusage
  MRB_SECCOMP_SET_SYSCALL(getrusage);
#endif

#ifdef __NR_sysinfo
  MRB_SECCOMP_SET_SYSCALL(sysinfo);
#endif

#ifdef __NR_times
  MRB_SECCOMP_SET_SYSCALL(times);
#endif

#ifdef __NR_ptrace
  MRB_SECCOMP_SET_SYSCALL(ptrace);
#endif

#ifdef __NR_getuid
  MRB_SECCOMP_SET_SYSCALL(getuid);
#endif

#ifdef __NR_syslog
  MRB_SECCOMP_SET_SYSCALL(syslog);
#endif

#ifdef __NR_getgid
  MRB_SECCOMP_SET_SYSCALL(getgid);
#endif

#ifdef __NR_setuid
  MRB_SECCOMP_SET_SYSCALL(setuid);
#endif

#ifdef __NR_setgid
  MRB_SECCOMP_SET_SYSCALL(setgid);
#endif

#ifdef __NR_geteuid
  MRB_SECCOMP_SET_SYSCALL(geteuid);
#endif

#ifdef __NR_getegid
  MRB_SECCOMP_SET_SYSCALL(getegid);
#endif

#ifdef __NR_setpgid
  MRB_SECCOMP_SET_SYSCALL(setpgid);
#endif

#ifdef __NR_getppid
  MRB_SECCOMP_SET_SYSCALL(getppid);
#endif

#ifdef __NR_getpgrp
  MRB_SECCOMP_SET_SYSCALL(getpgrp);
#endif

#ifdef __NR_setsid
  MRB_SECCOMP_SET_SYSCALL(setsid);
#endif

#ifdef __NR_setreuid
  MRB_SECCOMP_SET_SYSCALL(setreuid);
#endif

#ifdef __NR_setregid
  MRB_SECCOMP_SET_SYSCALL(setregid);
#endif

#ifdef __NR_getgroups
  MRB_SECCOMP_SET_SYSCALL(getgroups);
#endif

#ifdef __NR_setgroups
  MRB_SECCOMP_SET_SYSCALL(setgroups);
#endif

#ifdef __NR_setresuid
  MRB_SECCOMP_SET_SYSCALL(setresuid);
#endif

#ifdef __NR_getresuid
  MRB_SECCOMP_SET_SYSCALL(getresuid);
#endif

#ifdef __NR_setresgid
  MRB_SECCOMP_SET_SYSCALL(setresgid);
#endif

#ifdef __NR_getresgid
  MRB_SECCOMP_SET_SYSCALL(getresgid);
#endif

#ifdef __NR_getpgid
  MRB_SECCOMP_SET_SYSCALL(getpgid);
#endif

#ifdef __NR_setfsuid
  MRB_SECCOMP_SET_SYSCALL(setfsuid);
#endif

#ifdef __NR_setfsgid
  MRB_SECCOMP_SET_SYSCALL(setfsgid);
#endif

#ifdef __NR_getsid
  MRB_SECCOMP_SET_SYSCALL(getsid);
#endif

#ifdef __NR_capget
  MRB_SECCOMP_SET_SYSCALL(capget);
#endif

#ifdef __NR_capset
  MRB_SECCOMP_SET_SYSCALL(capset);
#endif

#ifdef __NR_rt_sigpending
  MRB_SECCOMP_SET_SYSCALL(rt_sigpending);
#endif

#ifdef __NR_rt_sigtimedwait
  MRB_SECCOMP_SET_SYSCALL(rt_sigtimedwait);
#endif

#ifdef __NR_rt_sigqueueinfo
  MRB_SECCOMP_SET_SYSCALL(rt_sigqueueinfo);
#endif

#ifdef __NR_rt_sigsuspend
  MRB_SECCOMP_SET_SYSCALL(rt_sigsuspend);
#endif

#ifdef __NR_sigaltstack
  MRB_SECCOMP_SET_SYSCALL(sigaltstack);
#endif

#ifdef __NR_utime
  MRB_SECCOMP_SET_SYSCALL(utime);
#endif

#ifdef __NR_mknod
  MRB_SECCOMP_SET_SYSCALL(mknod);
#endif

#ifdef __NR_uselib
  MRB_SECCOMP_SET_SYSCALL(uselib);
#endif

#ifdef __NR_personality
  MRB_SECCOMP_SET_SYSCALL(personality);
#endif

#ifdef __NR_ustat
  MRB_SECCOMP_SET_SYSCALL(ustat);
#endif

#ifdef __NR_statfs
  MRB_SECCOMP_SET_SYSCALL(statfs);
#endif

#ifdef __NR_fstatfs
  MRB_SECCOMP_SET_SYSCALL(fstatfs);
#endif

#ifdef __NR_sysfs
  MRB_SECCOMP_SET_SYSCALL(sysfs);
#endif

#ifdef __NR_getpriority
  MRB_SECCOMP_SET_SYSCALL(getpriority);
#endif

#ifdef __NR_setpriority
  MRB_SECCOMP_SET_SYSCALL(setpriority);
#endif

#ifdef __NR_sched_setparam
  MRB_SECCOMP_SET_SYSCALL(sched_setparam);
#endif

#ifdef __NR_sched_getparam
  MRB_SECCOMP_SET_SYSCALL(sched_getparam);
#endif

#ifdef __NR_sched_setscheduler
  MRB_SECCOMP_SET_SYSCALL(sched_setscheduler);
#endif

#ifdef __NR_sched_getscheduler
  MRB_SECCOMP_SET_SYSCALL(sched_getscheduler);
#endif

#ifdef __NR_sched_get_priority_max
  MRB_SECCOMP_SET_SYSCALL(sched_get_priority_max);
#endif

#ifdef __NR_sched_get_priority_min
  MRB_SECCOMP_SET_SYSCALL(sched_get_priority_min);
#endif

#ifdef __NR_sched_rr_get_interval
  MRB_SECCOMP_SET_SYSCALL(sched_rr_get_interval);
#endif

#ifdef __NR_mlock
  MRB_SECCOMP_SET_SYSCALL(mlock);
#endif

#ifdef __NR_munlock
  MRB_SECCOMP_SET_SYSCALL(munlock);
#endif

#ifdef __NR_mlockall
  MRB_SECCOMP_SET_SYSCALL(mlockall);
#endif

#ifdef __NR_munlockall
  MRB_SECCOMP_SET_SYSCALL(munlockall);
#endif

#ifdef __NR_vhangup
  MRB_SECCOMP_SET_SYSCALL(vhangup);
#endif

#ifdef __NR_modify_ldt
  MRB_SECCOMP_SET_SYSCALL(modify_ldt);
#endif

#ifdef __NR_pivot_root
  MRB_SECCOMP_SET_SYSCALL(pivot_root);
#endif

#ifdef __NR__sysctl
  MRB_SECCOMP_SET_SYSCALL(_sysctl);
#endif

#ifdef __NR_prctl
  MRB_SECCOMP_SET_SYSCALL(prctl);
#endif

#ifdef __NR_arch_prctl
  MRB_SECCOMP_SET_SYSCALL(arch_prctl);
#endif

#ifdef __NR_adjtimex
  MRB_SECCOMP_SET_SYSCALL(adjtimex);
#endif

#ifdef __NR_setrlimit
  MRB_SECCOMP_SET_SYSCALL(setrlimit);
#endif

#ifdef __NR_chroot
  MRB_SECCOMP_SET_SYSCALL(chroot);
#endif

#ifdef __NR_sync
  MRB_SECCOMP_SET_SYSCALL(sync);
#endif

#ifdef __NR_acct
  MRB_SECCOMP_SET_SYSCALL(acct);
#endif

#ifdef __NR_settimeofday
  MRB_SECCOMP_SET_SYSCALL(settimeofday);
#endif

#ifdef __NR_mount
  MRB_SECCOMP_SET_SYSCALL(mount);
#endif

#ifdef __NR_umount2
  MRB_SECCOMP_SET_SYSCALL(umount2);
#endif

#ifdef __NR_swapon
  MRB_SECCOMP_SET_SYSCALL(swapon);
#endif

#ifdef __NR_swapoff
  MRB_SECCOMP_SET_SYSCALL(swapoff);
#endif

#ifdef __NR_reboot
  MRB_SECCOMP_SET_SYSCALL(reboot);
#endif

#ifdef __NR_sethostname
  MRB_SECCOMP_SET_SYSCALL(sethostname);
#endif

#ifdef __NR_setdomainname
  MRB_SECCOMP_SET_SYSCALL(setdomainname);
#endif

#ifdef __NR_iopl
  MRB_SECCOMP_SET_SYSCALL(iopl);
#endif

#ifdef __NR_ioperm
  MRB_SECCOMP_SET_SYSCALL(ioperm);
#endif

#ifdef __NR_create_module
  MRB_SECCOMP_SET_SYSCALL(create_module);
#endif

#ifdef __NR_init_module
  MRB_SECCOMP_SET_SYSCALL(init_module);
#endif

#ifdef __NR_delete_module
  MRB_SECCOMP_SET_SYSCALL(delete_module);
#endif

#ifdef __NR_get_kernel_syms
  MRB_SECCOMP_SET_SYSCALL(get_kernel_syms);
#endif

#ifdef __NR_query_module
  MRB_SECCOMP_SET_SYSCALL(query_module);
#endif

#ifdef __NR_quotactl
  MRB_SECCOMP_SET_SYSCALL(quotactl);
#endif

#ifdef __NR_nfsservctl
  MRB_SECCOMP_SET_SYSCALL(nfsservctl);
#endif

#ifdef __NR_getpmsg
  MRB_SECCOMP_SET_SYSCALL(getpmsg);
#endif

#ifdef __NR_putpmsg
  MRB_SECCOMP_SET_SYSCALL(putpmsg);
#endif

#ifdef __NR_afs_syscall
  MRB_SECCOMP_SET_SYSCALL(afs_syscall);
#endif

#ifdef __NR_tuxcall
  MRB_SECCOMP_SET_SYSCALL(tuxcall);
#endif

#ifdef __NR_security
  MRB_SECCOMP_SET_SYSCALL(security);
#endif

#ifdef __NR_gettid
  MRB_SECCOMP_SET_SYSCALL(gettid);
#endif

#ifdef __NR_readahead
  MRB_SECCOMP_SET_SYSCALL(readahead);
#endif

#ifdef __NR_setxattr
  MRB_SECCOMP_SET_SYSCALL(setxattr);
#endif

#ifdef __NR_lsetxattr
  MRB_SECCOMP_SET_SYSCALL(lsetxattr);
#endif

#ifdef __NR_fsetxattr
  MRB_SECCOMP_SET_SYSCALL(fsetxattr);
#endif

#ifdef __NR_getxattr
  MRB_SECCOMP_SET_SYSCALL(getxattr);
#endif

#ifdef __NR_lgetxattr
  MRB_SECCOMP_SET_SYSCALL(lgetxattr);
#endif

#ifdef __NR_fgetxattr
  MRB_SECCOMP_SET_SYSCALL(fgetxattr);
#endif

#ifdef __NR_listxattr
  MRB_SECCOMP_SET_SYSCALL(listxattr);
#endif

#ifdef __NR_llistxattr
  MRB_SECCOMP_SET_SYSCALL(llistxattr);
#endif

#ifdef __NR_flistxattr
  MRB_SECCOMP_SET_SYSCALL(flistxattr);
#endif

#ifdef __NR_removexattr
  MRB_SECCOMP_SET_SYSCALL(removexattr);
#endif

#ifdef __NR_lremovexattr
  MRB_SECCOMP_SET_SYSCALL(lremovexattr);
#endif

#ifdef __NR_fremovexattr
  MRB_SECCOMP_SET_SYSCALL(fremovexattr);
#endif

#ifdef __NR_tkill
  MRB_SECCOMP_SET_SYSCALL(tkill);
#endif

#ifdef __NR_time
  MRB_SECCOMP_SET_SYSCALL(time);
#endif

#ifdef __NR_futex
  MRB_SECCOMP_SET_SYSCALL(futex);
#endif

#ifdef __NR_sched_setaffinity
  MRB_SECCOMP_SET_SYSCALL(sched_setaffinity);
#endif

#ifdef __NR_sched_getaffinity
  MRB_SECCOMP_SET_SYSCALL(sched_getaffinity);
#endif

#ifdef __NR_set_thread_area
  MRB_SECCOMP_SET_SYSCALL(set_thread_area);
#endif

#ifdef __NR_io_setup
  MRB_SECCOMP_SET_SYSCALL(io_setup);
#endif

#ifdef __NR_io_destroy
  MRB_SECCOMP_SET_SYSCALL(io_destroy);
#endif

#ifdef __NR_io_getevents
  MRB_SECCOMP_SET_SYSCALL(io_getevents);
#endif

#ifdef __NR_io_submit
  MRB_SECCOMP_SET_SYSCALL(io_submit);
#endif

#ifdef __NR_io_cancel
  MRB_SECCOMP_SET_SYSCALL(io_cancel);
#endif

#ifdef __NR_get_thread_area
  MRB_SECCOMP_SET_SYSCALL(get_thread_area);
#endif

#ifdef __NR_lookup_dcookie
  MRB_SECCOMP_SET_SYSCALL(lookup_dcookie);
#endif

#ifdef __NR_epoll_create
  MRB_SECCOMP_SET_SYSCALL(epoll_create);
#endif

#ifdef __NR_epoll_ctl_old
  MRB_SECCOMP_SET_SYSCALL(epoll_ctl_old);
#endif

#ifdef __NR_epoll_wait_old
  MRB_SECCOMP_SET_SYSCALL(epoll_wait_old);
#endif

#ifdef __NR_remap_file_pages
  MRB_SECCOMP_SET_SYSCALL(remap_file_pages);
#endif

#ifdef __NR_getdents64
  MRB_SECCOMP_SET_SYSCALL(getdents64);
#endif

#ifdef __NR_set_tid_address
  MRB_SECCOMP_SET_SYSCALL(set_tid_address);
#endif

#ifdef __NR_restart_syscall
  MRB_SECCOMP_SET_SYSCALL(restart_syscall);
#endif

#ifdef __NR_semtimedop
  MRB_SECCOMP_SET_SYSCALL(semtimedop);
#endif

#ifdef __NR_fadvise64
  MRB_SECCOMP_SET_SYSCALL(fadvise64);
#endif

#ifdef __NR_timer_create
  MRB_SECCOMP_SET_SYSCALL(timer_create);
#endif

#ifdef __NR_timer_settime
  MRB_SECCOMP_SET_SYSCALL(timer_settime);
#endif

#ifdef __NR_timer_gettime
  MRB_SECCOMP_SET_SYSCALL(timer_gettime);
#endif

#ifdef __NR_timer_getoverrun
  MRB_SECCOMP_SET_SYSCALL(timer_getoverrun);
#endif

#ifdef __NR_timer_delete
  MRB_SECCOMP_SET_SYSCALL(timer_delete);
#endif

#ifdef __NR_clock_settime
  MRB_SECCOMP_SET_SYSCALL(clock_settime);
#endif

#ifdef __NR_clock_gettime
  MRB_SECCOMP_SET_SYSCALL(clock_gettime);
#endif

#ifdef __NR_clock_getres
  MRB_SECCOMP_SET_SYSCALL(clock_getres);
#endif

#ifdef __NR_clock_nanosleep
  MRB_SECCOMP_SET_SYSCALL(clock_nanosleep);
#endif

#ifdef __NR_exit_group
  MRB_SECCOMP_SET_SYSCALL(exit_group);
#endif

#ifdef __NR_epoll_wait
  MRB_SECCOMP_SET_SYSCALL(epoll_wait);
#endif

#ifdef __NR_epoll_ctl
  MRB_SECCOMP_SET_SYSCALL(epoll_ctl);
#endif

#ifdef __NR_tgkill
  MRB_SECCOMP_SET_SYSCALL(tgkill);
#endif

#ifdef __NR_utimes
  MRB_SECCOMP_SET_SYSCALL(utimes);
#endif

#ifdef __NR_vserver
  MRB_SECCOMP_SET_SYSCALL(vserver);
#endif

#ifdef __NR_mbind
  MRB_SECCOMP_SET_SYSCALL(mbind);
#endif

#ifdef __NR_set_mempolicy
  MRB_SECCOMP_SET_SYSCALL(set_mempolicy);
#endif

#ifdef __NR_get_mempolicy
  MRB_SECCOMP_SET_SYSCALL(get_mempolicy);
#endif

#ifdef __NR_mq_open
  MRB_SECCOMP_SET_SYSCALL(mq_open);
#endif

#ifdef __NR_mq_unlink
  MRB_SECCOMP_SET_SYSCALL(mq_unlink);
#endif

#ifdef __NR_mq_timedsend
  MRB_SECCOMP_SET_SYSCALL(mq_timedsend);
#endif

#ifdef __NR_mq_timedreceive
  MRB_SECCOMP_SET_SYSCALL(mq_timedreceive);
#endif

#ifdef __NR_mq_notify
  MRB_SECCOMP_SET_SYSCALL(mq_notify);
#endif

#ifdef __NR_mq_getsetattr
  MRB_SECCOMP_SET_SYSCALL(mq_getsetattr);
#endif

#ifdef __NR_kexec_load
  MRB_SECCOMP_SET_SYSCALL(kexec_load);
#endif

#ifdef __NR_waitid
  MRB_SECCOMP_SET_SYSCALL(waitid);
#endif

#ifdef __NR_add_key
  MRB_SECCOMP_SET_SYSCALL(add_key);
#endif

#ifdef __NR_request_key
  MRB_SECCOMP_SET_SYSCALL(request_key);
#endif

#ifdef __NR_keyctl
  MRB_SECCOMP_SET_SYSCALL(keyctl);
#endif

#ifdef __NR_ioprio_set
  MRB_SECCOMP_SET_SYSCALL(ioprio_set);
#endif

#ifdef __NR_ioprio_get
  MRB_SECCOMP_SET_SYSCALL(ioprio_get);
#endif

#ifdef __NR_inotify_init
  MRB_SECCOMP_SET_SYSCALL(inotify_init);
#endif

#ifdef __NR_inotify_add_watch
  MRB_SECCOMP_SET_SYSCALL(inotify_add_watch);
#endif

#ifdef __NR_inotify_rm_watch
  MRB_SECCOMP_SET_SYSCALL(inotify_rm_watch);
#endif

#ifdef __NR_migrate_pages
  MRB_SECCOMP_SET_SYSCALL(migrate_pages);
#endif

#ifdef __NR_openat
  MRB_SECCOMP_SET_SYSCALL(openat);
#endif

#ifdef __NR_mkdirat
  MRB_SECCOMP_SET_SYSCALL(mkdirat);
#endif

#ifdef __NR_mknodat
  MRB_SECCOMP_SET_SYSCALL(mknodat);
#endif

#ifdef __NR_fchownat
  MRB_SECCOMP_SET_SYSCALL(fchownat);
#endif

#ifdef __NR_futimesat
  MRB_SECCOMP_SET_SYSCALL(futimesat);
#endif

#ifdef __NR_newfstatat
  MRB_SECCOMP_SET_SYSCALL(newfstatat);
#endif

#ifdef __NR_unlinkat
  MRB_SECCOMP_SET_SYSCALL(unlinkat);
#endif

#ifdef __NR_renameat
  MRB_SECCOMP_SET_SYSCALL(renameat);
#endif

#ifdef __NR_linkat
  MRB_SECCOMP_SET_SYSCALL(linkat);
#endif

#ifdef __NR_symlinkat
  MRB_SECCOMP_SET_SYSCALL(symlinkat);
#endif

#ifdef __NR_readlinkat
  MRB_SECCOMP_SET_SYSCALL(readlinkat);
#endif

#ifdef __NR_fchmodat
  MRB_SECCOMP_SET_SYSCALL(fchmodat);
#endif

#ifdef __NR_faccessat
  MRB_SECCOMP_SET_SYSCALL(faccessat);
#endif

#ifdef __NR_pselect6
  MRB_SECCOMP_SET_SYSCALL(pselect6);
#endif

#ifdef __NR_ppoll
  MRB_SECCOMP_SET_SYSCALL(ppoll);
#endif

#ifdef __NR_unshare
  MRB_SECCOMP_SET_SYSCALL(unshare);
#endif

#ifdef __NR_set_robust_list
  MRB_SECCOMP_SET_SYSCALL(set_robust_list);
#endif

#ifdef __NR_get_robust_list
  MRB_SECCOMP_SET_SYSCALL(get_robust_list);
#endif

#ifdef __NR_splice
  MRB_SECCOMP_SET_SYSCALL(splice);
#endif

#ifdef __NR_tee
  MRB_SECCOMP_SET_SYSCALL(tee);
#endif

#ifdef __NR_sync_file_range
  MRB_SECCOMP_SET_SYSCALL(sync_file_range);
#endif

#ifdef __NR_vmsplice
  MRB_SECCOMP_SET_SYSCALL(vmsplice);
#endif

#ifdef __NR_move_pages
  MRB_SECCOMP_SET_SYSCALL(move_pages);
#endif

#ifdef __NR_utimensat
  MRB_SECCOMP_SET_SYSCALL(utimensat);
#endif

#ifdef __NR_epoll_pwait
  MRB_SECCOMP_SET_SYSCALL(epoll_pwait);
#endif

#ifdef __NR_signalfd
  MRB_SECCOMP_SET_SYSCALL(signalfd);
#endif

#ifdef __NR_timerfd
  MRB_SECCOMP_SET_SYSCALL(timerfd);
#endif

#ifdef __NR_eventfd
  MRB_SECCOMP_SET_SYSCALL(eventfd);
#endif

#ifdef __NR_fallocate
  MRB_SECCOMP_SET_SYSCALL(fallocate);
#endif

#ifdef __NR_timerfd_settime
  MRB_SECCOMP_SET_SYSCALL(timerfd_settime);
#endif

#ifdef __NR_timerfd_gettime
  MRB_SECCOMP_SET_SYSCALL(timerfd_gettime);
#endif

#ifdef __NR_accept4
  MRB_SECCOMP_SET_SYSCALL(accept4);
#endif

#ifdef __NR_signalfd4
  MRB_SECCOMP_SET_SYSCALL(signalfd4);
#endif

#ifdef __NR_eventfd2
  MRB_SECCOMP_SET_SYSCALL(eventfd2);
#endif

#ifdef __NR_epoll_create1
  MRB_SECCOMP_SET_SYSCALL(epoll_create1);
#endif

#ifdef __NR_dup3
  MRB_SECCOMP_SET_SYSCALL(dup3);
#endif

#ifdef __NR_pipe2
  MRB_SECCOMP_SET_SYSCALL(pipe2);
#endif

#ifdef __NR_inotify_init1
  MRB_SECCOMP_SET_SYSCALL(inotify_init1);
#endif

#ifdef __NR_preadv
  MRB_SECCOMP_SET_SYSCALL(preadv);
#endif

#ifdef __NR_pwritev
  MRB_SECCOMP_SET_SYSCALL(pwritev);
#endif

#ifdef __NR_rt_tgsigqueueinfo
  MRB_SECCOMP_SET_SYSCALL(rt_tgsigqueueinfo);
#endif

#ifdef __NR_perf_event_open
  MRB_SECCOMP_SET_SYSCALL(perf_event_open);
#endif

#ifdef __NR_recvmmsg
  MRB_SECCOMP_SET_SYSCALL(recvmmsg);
#endif

#ifdef __NR_fanotify_init
  MRB_SECCOMP_SET_SYSCALL(fanotify_init);
#endif

#ifdef __NR_fanotify_mark
  MRB_SECCOMP_SET_SYSCALL(fanotify_mark);
#endif

#ifdef __NR_prlimit64
  MRB_SECCOMP_SET_SYSCALL(prlimit64);
#endif

#ifdef __NR_name_to_handle_at
  MRB_SECCOMP_SET_SYSCALL(name_to_handle_at);
#endif

#ifdef __NR_open_by_handle_at
  MRB_SECCOMP_SET_SYSCALL(open_by_handle_at);
#endif

#ifdef __NR_clock_adjtime
  MRB_SECCOMP_SET_SYSCALL(clock_adjtime);
#endif

#ifdef __NR_syncfs
  MRB_SECCOMP_SET_SYSCALL(syncfs);
#endif

#ifdef __NR_sendmmsg
  MRB_SECCOMP_SET_SYSCALL(sendmmsg);
#endif

#ifdef __NR_setns
  MRB_SECCOMP_SET_SYSCALL(setns);
#endif

#ifdef __NR_getcpu
  MRB_SECCOMP_SET_SYSCALL(getcpu);
#endif

#ifdef __NR_process_vm_readv
  MRB_SECCOMP_SET_SYSCALL(process_vm_readv);
#endif

#ifdef __NR_process_vm_writev
  MRB_SECCOMP_SET_SYSCALL(process_vm_writev);
#endif

#ifdef __NR_kcmp
  MRB_SECCOMP_SET_SYSCALL(kcmp);
#endif

#ifdef __NR_finit_module
  MRB_SECCOMP_SET_SYSCALL(finit_module);
#endif

#ifdef __NR_sched_setattr
  MRB_SECCOMP_SET_SYSCALL(sched_setattr);
#endif

#ifdef __NR_sched_getattr
  MRB_SECCOMP_SET_SYSCALL(sched_getattr);
#endif

#ifdef __NR_renameat2
  MRB_SECCOMP_SET_SYSCALL(renameat2);
#endif

#ifdef __NR_seccomp
  MRB_SECCOMP_SET_SYSCALL(seccomp);
#endif

#ifdef __NR_getrandom
  MRB_SECCOMP_SET_SYSCALL(getrandom);
#endif

#ifdef __NR_memfd_create
  MRB_SECCOMP_SET_SYSCALL(memfd_create);
#endif

#ifdef __NR_kexec_file_load
  MRB_SECCOMP_SET_SYSCALL(kexec_file_load);
#endif

#ifdef __NR_bpf
  MRB_SECCOMP_SET_SYSCALL(bpf);
#endif

  return table;
}
