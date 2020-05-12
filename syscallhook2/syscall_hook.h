#ifndef SYSCALL_HOOK_H
#define SYSCALL_HOOK_H

#define debug(fmt, args...)	pr_info("CPU %d " fmt, smp_processor_id(), ##args)
#define alert(fmt, args...)	pr_alert("CPU %d " fmt, smp_processor_id(), ##args)

#include<asm/syscall.h>
#include<linux/unistd.h>
#include<linux/string.h>
#include<linux/sched.h>

#define MSR_LSTAR	0xc0000082
void (*syscall_handler)(void);
long unsigned int original_dispatcher;
extern void __fake_syscall_dispatcher(void);
char *syscall_num_to_name(int);

static inline uint64_t get_dispatcher_from_msr(void)
{
	uint64_t address;

	rdmsrl(MSR_LSTAR, address);

	return address;
}

static inline void init_hook_syscall(void)
{
	uint64_t address = get_dispatcher_from_msr();

	original_dispatcher = address;
	syscall_handler = (void (*)(void)) address;
}

static inline void hook_syscall(void)
{
	debug("hook\n");
	uint32_t low;

	low = (uint32_t) (((uint64_t)__fake_syscall_dispatcher) & 0xffffffff);

	wrmsr(MSR_LSTAR, low, 0xffffffff);
}

static inline void unhook_syscall(void)
{
	debug("unhook\n");

	uint64_t address = get_dispatcher_from_msr();
	if ((uintptr_t)address != (uintptr_t)__fake_syscall_dispatcher ) {
		alert("already unhooked\ncurrent dispatcher: 0x%lx\toriginal dispatcher: 0x%lx\n", 
		       address, original_dispatcher);
	}

	wrmsr(MSR_LSTAR, (uint32_t) (original_dispatcher & 0xffffffff), 0xffffffff);
}

/////////////////////////////////////////////////////////////////////
// Hook System Call
////////////////////////////////////////////////////////////////////
DEFINE_PER_CPU(uint64_t, rsp_scratch);
DEFINE_PER_CPU(uint64_t, syscall_num);

int pre_hooking(int num,  void *arg1, void *arg2)
{
	int flag = 0;
	char *fixed_arg1;
	char *syscall_name;	

    syscall_name = syscall_num_to_name(num);

	if(num == __NR_unlink){
		debug("unlink hook\n", arg1);
		fixed_arg1 = strrchr(arg1, '/');
		if(fixed_arg1 == NULL){
			fixed_arg1 = arg1;
		}else{
			fixed_arg1 += 1;
		}
		if(strcmp(current->comm, fixed_arg1)==0){
			flag = 1;
			debug("detect self-deleting.\n");
		}
	}

	debug("pid: [%d] task: [%s] syscall: [%s] arg1: [%s] arg2: [%s]", current->pid, current->comm, syscall_name, arg1, arg2);
	return flag;
}

char *syscall_num_to_name(int num){
	char *syscall_name;

	if (num == __NR_read)
		syscall_name = "read";
	else if (num == __NR_write)
		syscall_name = "write";
	else if (num == __NR_open)
		syscall_name = "open";
	else if (num == __NR_close)
		syscall_name = "close";
	else if (num == __NR_stat)
		syscall_name = "stat";
	else if (num == __NR_fstat)
		syscall_name = "fstat";
	else if (num == __NR_lstat)
		syscall_name = "lstat";
	else if (num == __NR_poll)
		syscall_name = "poll";
	else if (num == __NR_lseek)
		syscall_name = "lseek";
	else if (num == __NR_mmap)
		syscall_name = "mmap";
	else if (num == __NR_mprotect)
		syscall_name = "mprotect";
	else if (num == __NR_munmap)
		syscall_name = "munmap";
	else if (num == __NR_brk)
		syscall_name = "brk";
	else if (num == __NR_rt_sigaction)
		syscall_name = "rt_sigaction";
	else if (num == __NR_rt_sigprocmask)
		syscall_name = "rt_sigprocmask";
	else if (num == __NR_rt_sigreturn)
		syscall_name = "rt_sigreturn";
	else if (num == __NR_ioctl)
		syscall_name = "ioctl";
	else if (num == __NR_pread64)
		syscall_name = "pread64";
	else if (num == __NR_pwrite64)
		syscall_name = "pwrite64";
	else if (num == __NR_readv)
		syscall_name = "readv";
	else if (num == __NR_writev)
		syscall_name = "writev";
	else if (num == __NR_access)
		syscall_name = "access";
	else if (num == __NR_pipe)
		syscall_name = "pipe";
	else if (num == __NR_select)
		syscall_name = "select";
	else if (num == __NR_sched_yield)
		syscall_name = "sched_yield";
	else if (num == __NR_mremap)
		syscall_name = "mremap";
	else if (num == __NR_msync)
		syscall_name = "msync";
	else if (num == __NR_mincore)
		syscall_name = "mincore";
	else if (num == __NR_madvise)
		syscall_name = "madvise";
	else if (num == __NR_shmget)
		syscall_name = "shmget";
	else if (num == __NR_shmat)
		syscall_name = "shmat";
	else if (num == __NR_shmctl)
		syscall_name = "shmctl";
	else if (num == __NR_dup)
		syscall_name = "dup";
	else if (num == __NR_dup2)
		syscall_name = "dup2";
	else if (num == __NR_pause)
		syscall_name = "pause";
	else if (num == __NR_nanosleep)
		syscall_name = "nanosleep";
	else if (num == __NR_getitimer)
		syscall_name = "getitimer";
	else if (num == __NR_alarm)
		syscall_name = "alarm";
	else if (num == __NR_setitimer)
		syscall_name = "setitimer";
	else if (num == __NR_getpid)
		syscall_name = "getpid";
	else if (num == __NR_sendfile)
		syscall_name = "sendfile";
	else if (num == __NR_socket)
		syscall_name = "socket";
	else if (num == __NR_connect)
		syscall_name = "connect";
	else if (num == __NR_accept)
		syscall_name = "accept";
	else if (num == __NR_sendto)
		syscall_name = "sendto";
	else if (num == __NR_recvfrom)
		syscall_name = "recvfrom";
	else if (num == __NR_sendmsg)
		syscall_name = "sendmsg";
	else if (num == __NR_recvmsg)
		syscall_name = "recvmsg";
	else if (num == __NR_shutdown)
		syscall_name = "shutdown";
	else if (num == __NR_bind)
		syscall_name = "bind";
	else if (num == __NR_listen)
		syscall_name = "listen";
	else if (num == __NR_getsockname)
		syscall_name = "getsockname";
	else if (num == __NR_getpeername)
		syscall_name = "getpeername";
	else if (num == __NR_socketpair)
		syscall_name = "socketpair";
	else if (num == __NR_setsockopt)
		syscall_name = "setsockopt";
	else if (num == __NR_getsockopt)
		syscall_name = "getsockopt";
	else if (num == __NR_clone)
		syscall_name = "clone";
	else if (num == __NR_fork)
		syscall_name = "fork";
	else if (num == __NR_vfork)
		syscall_name = "vfork";
	else if (num == __NR_execve)
		syscall_name = "execve";
	else if (num == __NR_exit)
		syscall_name = "exit";
	else if (num == __NR_wait4)
		syscall_name = "wait4";
	else if (num == __NR_kill)
		syscall_name = "kill";
	else if (num == __NR_uname)
		syscall_name = "uname";
	else if (num == __NR_semget)
		syscall_name = "semget";
	else if (num == __NR_semop)
		syscall_name = "semop";
	else if (num == __NR_semctl)
		syscall_name = "semctl";
	else if (num == __NR_shmdt)
		syscall_name = "shmdt";
	else if (num == __NR_msgget)
		syscall_name = "msgget";
	else if (num == __NR_msgsnd)
		syscall_name = "msgsnd";
	else if (num == __NR_msgrcv)
		syscall_name = "msgrcv";
	else if (num == __NR_msgctl)
		syscall_name = "msgctl";
	else if (num == __NR_fcntl)
		syscall_name = "fcntl";
	else if (num == __NR_flock)
		syscall_name = "flock";
	else if (num == __NR_fsync)
		syscall_name = "fsync";
	else if (num == __NR_fdatasync)
		syscall_name = "fdatasync";
	else if (num == __NR_truncate)
		syscall_name = "truncate";
	else if (num == __NR_ftruncate)
		syscall_name = "ftruncate";
	else if (num == __NR_getdents)
		syscall_name = "getdents";
	else if (num == __NR_getcwd)
		syscall_name = "getcwd";
	else if (num == __NR_chdir)
		syscall_name = "chdir";
	else if (num == __NR_fchdir)
		syscall_name = "fchdir";
	else if (num == __NR_rename)
		syscall_name = "rename";
	else if (num == __NR_mkdir)
		syscall_name = "mkdir";
	else if (num == __NR_rmdir)
		syscall_name = "rmdir";
	else if (num == __NR_creat)
		syscall_name = "creat";
	else if (num == __NR_link)
		syscall_name = "link";
	else if (num == __NR_unlink)
		syscall_name = "unlink";
	else if (num == __NR_symlink)
		syscall_name = "symlink";
	else if (num == __NR_readlink)
		syscall_name = "readlink";
	else if (num == __NR_chmod)
		syscall_name = "chmod";
	else if (num == __NR_fchmod)
		syscall_name = "fchmod";
	else if (num == __NR_chown)
		syscall_name = "chown";
	else if (num == __NR_fchown)
		syscall_name = "fchown";
	else if (num == __NR_lchown)
		syscall_name = "lchown";
	else if (num == __NR_umask)
		syscall_name = "umask";
	else if (num == __NR_gettimeofday)
		syscall_name = "gettimeofday";
	else if (num == __NR_getrlimit)
		syscall_name = "getrlimit";
	else if (num == __NR_getrusage)
		syscall_name = "getrusage";
	else if (num == __NR_sysinfo)
		syscall_name = "sysinfo";
	else if (num == __NR_times)
		syscall_name = "times";
	else if (num == __NR_ptrace)
		syscall_name = "ptrace";
	else if (num == __NR_getuid)
		syscall_name = "getuid";
	else if (num == __NR_syslog)
		syscall_name = "syslog";
	else if (num == __NR_getgid)
		syscall_name = "getgid";
	else if (num == __NR_setuid)
		syscall_name = "setuid";
	else if (num == __NR_setgid)
		syscall_name = "setgid";
	else if (num == __NR_geteuid)
		syscall_name = "geteuid";
	else if (num == __NR_getegid)
		syscall_name = "getegid";
	else if (num == __NR_setpgid)
		syscall_name = "setpgid";
	else if (num == __NR_getppid)
		syscall_name = "getppid";
	else if (num == __NR_getpgrp)
		syscall_name = "getpgrp";
	else if (num == __NR_setsid)
		syscall_name = "setsid";
	else if (num == __NR_setreuid)
		syscall_name = "setreuid";
	else if (num == __NR_setregid)
		syscall_name = "setregid";
	else if (num == __NR_getgroups)
		syscall_name = "getgroups";
	else if (num == __NR_setgroups)
		syscall_name = "setgroups";
	else if (num == __NR_setresuid)
		syscall_name = "setresuid";
	else if (num == __NR_getresuid)
		syscall_name = "getresuid";
	else if (num == __NR_setresgid)
		syscall_name = "setresgid";
	else if (num == __NR_getresgid)
		syscall_name = "getresgid";
	else if (num == __NR_getpgid)
		syscall_name = "getpgid";
	else if (num == __NR_setfsuid)
		syscall_name = "setfsuid";
	else if (num == __NR_setfsgid)
		syscall_name = "setfsgid";
	else if (num == __NR_getsid)
		syscall_name = "getsid";
	else if (num == __NR_capget)
		syscall_name = "capget";
	else if (num == __NR_capset)
		syscall_name = "capset";
	else if (num == __NR_rt_sigpending)
		syscall_name = "rt_sigpending";
	else if (num == __NR_rt_sigtimedwait)
		syscall_name = "rt_sigtimedwait";
	else if (num == __NR_rt_sigqueueinfo)
		syscall_name = "rt_sigqueueinfo";
	else if (num == __NR_rt_sigsuspend)
		syscall_name = "rt_sigsuspend";
	else if (num == __NR_sigaltstack)
		syscall_name = "sigaltstack";
	else if (num == __NR_utime)
		syscall_name = "utime";
	else if (num == __NR_mknod)
		syscall_name = "mknod";
	else if (num == __NR_uselib)
		syscall_name = "uselib";
	else if (num == __NR_personality)
		syscall_name = "personality";
	else if (num == __NR_ustat)
		syscall_name = "ustat";
	else if (num == __NR_statfs)
		syscall_name = "statfs";
	else if (num == __NR_fstatfs)
		syscall_name = "fstatfs";
	else if (num == __NR_sysfs)
		syscall_name = "sysfs";
	else if (num == __NR_getpriority)
		syscall_name = "getpriority";
	else if (num == __NR_setpriority)
		syscall_name = "setpriority";
	else if (num == __NR_sched_setparam)
		syscall_name = "sched_setparam";
	else if (num == __NR_sched_getparam)
		syscall_name = "sched_getparam";
	else if (num == __NR_sched_setscheduler)
		syscall_name = "sched_setscheduler";
	else if (num == __NR_sched_getscheduler)
		syscall_name = "sched_getscheduler";
	else if (num == __NR_sched_get_priority_max)
		syscall_name = "sched_get_priority_max";
	else if (num == __NR_sched_get_priority_min)
		syscall_name = "sched_get_priority_min";
	else if (num == __NR_sched_rr_get_interval)
		syscall_name = "sched_rr_get_interval";
	else if (num == __NR_mlock)
		syscall_name = "mlock";
	else if (num == __NR_munlock)
		syscall_name = "munlock";
	else if (num == __NR_mlockall)
		syscall_name = "mlockall";
	else if (num == __NR_munlockall)
		syscall_name = "munlockall";
	else if (num == __NR_vhangup)
		syscall_name = "vhangup";
	else if (num == __NR_modify_ldt)
		syscall_name = "modify_ldt";
	else if (num == __NR_pivot_root)
		syscall_name = "pivot_root";
	else if (num == __NR__sysctl)
		syscall_name = "_sysctl";
	else if (num == __NR_prctl)
		syscall_name = "prctl";
	else if (num == __NR_arch_prctl)
		syscall_name = "arch_prctl";
	else if (num == __NR_adjtimex)
		syscall_name = "adjtimex";
	else if (num == __NR_setrlimit)
		syscall_name = "setrlimit";
	else if (num == __NR_chroot)
		syscall_name = "chroot";
	else if (num == __NR_sync)
		syscall_name = "sync";
	else if (num == __NR_acct)
		syscall_name = "acct";
	else if (num == __NR_settimeofday)
		syscall_name = "settimeofday";
	else if (num == __NR_mount)
		syscall_name = "mount";
	else if (num == __NR_umount2)
		syscall_name = "umount2";
	else if (num == __NR_swapon)
		syscall_name = "swapon";
	else if (num == __NR_swapoff)
		syscall_name = "swapoff";
	else if (num == __NR_reboot)
		syscall_name = "reboot";
	else if (num == __NR_sethostname)
		syscall_name = "sethostname";
	else if (num == __NR_setdomainname)
		syscall_name = "setdomainname";
	else if (num == __NR_iopl)
		syscall_name = "iopl";
	else if (num == __NR_ioperm)
		syscall_name = "ioperm";
	else if (num == __NR_create_module)
		syscall_name = "create_module";
	else if (num == __NR_init_module)
		syscall_name = "init_module";
	else if (num == __NR_delete_module)
		syscall_name = "delete_module";
	else if (num == __NR_get_kernel_syms)
		syscall_name = "get_kernel_syms";
	else if (num == __NR_query_module)
		syscall_name = "query_module";
	else if (num == __NR_quotactl)
		syscall_name = "quotactl";
	else if (num == __NR_nfsservctl)
		syscall_name = "nfsservctl";
	else if (num == __NR_getpmsg)
		syscall_name = "getpmsg";
	else if (num == __NR_putpmsg)
		syscall_name = "putpmsg";
	else if (num == __NR_afs_syscall)
		syscall_name = "afs_syscall";
	else if (num == __NR_tuxcall)
		syscall_name = "tuxcall";
	else if (num == __NR_security)
		syscall_name = "security";
	else if (num == __NR_gettid)
		syscall_name = "gettid";
	else if (num == __NR_readahead)
		syscall_name = "readahead";
	else if (num == __NR_setxattr)
		syscall_name = "setxattr";
	else if (num == __NR_lsetxattr)
		syscall_name = "lsetxattr";
	else if (num == __NR_fsetxattr)
		syscall_name = "fsetxattr";
	else if (num == __NR_getxattr)
		syscall_name = "getxattr";
	else if (num == __NR_lgetxattr)
		syscall_name = "lgetxattr";
	else if (num == __NR_fgetxattr)
		syscall_name = "fgetxattr";
	else if (num == __NR_listxattr)
		syscall_name = "listxattr";
	else if (num == __NR_llistxattr)
		syscall_name = "llistxattr";
	else if (num == __NR_flistxattr)
		syscall_name = "flistxattr";
	else if (num == __NR_removexattr)
		syscall_name = "removexattr";
	else if (num == __NR_lremovexattr)
		syscall_name = "lremovexattr";
	else if (num == __NR_fremovexattr)
		syscall_name = "fremovexattr";
	else if (num == __NR_tkill)
		syscall_name = "tkill";
	else if (num == __NR_time)
		syscall_name = "time";
	else if (num == __NR_futex)
		syscall_name = "futex";
	else if (num == __NR_sched_setaffinity)
		syscall_name = "sched_setaffinity";
	else if (num == __NR_sched_getaffinity)
		syscall_name = "sched_getaffinity";
	else if (num == __NR_set_thread_area)
		syscall_name = "set_thread_area";
	else if (num == __NR_io_setup)
		syscall_name = "io_setup";
	else if (num == __NR_io_destroy)
		syscall_name = "io_destroy";
	else if (num == __NR_io_getevents)
		syscall_name = "io_getevents";
	else if (num == __NR_io_submit)
		syscall_name = "io_submit";
	else if (num == __NR_io_cancel)
		syscall_name = "io_cancel";
	else if (num == __NR_get_thread_area)
		syscall_name = "get_thread_area";
	else if (num == __NR_lookup_dcookie)
		syscall_name = "lookup_dcookie";
	else if (num == __NR_epoll_create)
		syscall_name = "epoll_create";
	else if (num == __NR_epoll_ctl_old)
		syscall_name = "epoll_ctl_old";
	else if (num == __NR_epoll_wait_old)
		syscall_name = "epoll_wait_old";
	else if (num == __NR_remap_file_pages)
		syscall_name = "remap_file_pages";
	else if (num == __NR_getdents64)
		syscall_name = "getdents64";
	else if (num == __NR_set_tid_address)
		syscall_name = "set_tid_address";
	else if (num == __NR_restart_syscall)
		syscall_name = "restart_syscall";
	else if (num == __NR_semtimedop)
		syscall_name = "semtimedop";
	else if (num == __NR_fadvise64)
		syscall_name = "fadvise64";
	else if (num == __NR_timer_create)
		syscall_name = "timer_create";
	else if (num == __NR_timer_settime)
		syscall_name = "timer_settime";
	else if (num == __NR_timer_gettime)
		syscall_name = "timer_gettime";
	else if (num == __NR_timer_getoverrun)
		syscall_name = "timer_getoverrun";
	else if (num == __NR_timer_delete)
		syscall_name = "timer_delete";
	else if (num == __NR_clock_settime)
		syscall_name = "clock_settime";
	else if (num == __NR_clock_gettime)
		syscall_name = "clock_gettime";
	else if (num == __NR_clock_getres)
		syscall_name = "clock_getres";
	else if (num == __NR_clock_nanosleep)
		syscall_name = "clock_nanosleep";
	else if (num == __NR_exit_group)
		syscall_name = "exit_group";
	else if (num == __NR_epoll_wait)
		syscall_name = "epoll_wait";
	else if (num == __NR_epoll_ctl)
		syscall_name = "epoll_ctl";
	else if (num == __NR_tgkill)
		syscall_name = "tgkill";
	else if (num == __NR_utimes)
		syscall_name = "utimes";
	else if (num == __NR_vserver)
		syscall_name = "vserver";
	else if (num == __NR_mbind)
		syscall_name = "mbind";
	else if (num == __NR_set_mempolicy)
		syscall_name = "set_mempolicy";
	else if (num == __NR_get_mempolicy)
		syscall_name = "get_mempolicy";
	else if (num == __NR_mq_open)
		syscall_name = "mq_open";
	else if (num == __NR_mq_unlink)
		syscall_name = "mq_unlink";
	else if (num == __NR_mq_timedsend)
		syscall_name = "mq_timedsend";
	else if (num == __NR_mq_timedreceive)
		syscall_name = "mq_timedreceive";
	else if (num == __NR_mq_notify)
		syscall_name = "mq_notify";
	else if (num == __NR_mq_getsetattr)
		syscall_name = "mq_getsetattr";
	else if (num == __NR_kexec_load)
		syscall_name = "kexec_load";
	else if (num == __NR_waitid)
		syscall_name = "waitid";
	else if (num == __NR_add_key)
		syscall_name = "add_key";
	else if (num == __NR_request_key)
		syscall_name = "request_key";
	else if (num == __NR_keyctl)
		syscall_name = "keyctl";
	else if (num == __NR_ioprio_set)
		syscall_name = "ioprio_set";
	else if (num == __NR_ioprio_get)
		syscall_name = "ioprio_get";
	else if (num == __NR_inotify_init)
		syscall_name = "inotify_init";
	else if (num == __NR_inotify_add_watch)
		syscall_name = "inotify_add_watch";
	else if (num == __NR_inotify_rm_watch)
		syscall_name = "inotify_rm_watch";
	else if (num == __NR_migrate_pages)
		syscall_name = "migrate_pages";
	else if (num == __NR_openat)
		syscall_name = "openat";
	else if (num == __NR_mkdirat)
		syscall_name = "mkdirat";
	else if (num == __NR_mknodat)
		syscall_name = "mknodat";
	else if (num == __NR_fchownat)
		syscall_name = "fchownat";
	else if (num == __NR_futimesat)
		syscall_name = "futimesat";
	else if (num == __NR_newfstatat)
		syscall_name = "newfstatat";
	else if (num == __NR_unlinkat)
		syscall_name = "unlinkat";
	else if (num == __NR_renameat)
		syscall_name = "renameat";
	else if (num == __NR_linkat)
		syscall_name = "linkat";
	else if (num == __NR_symlinkat)
		syscall_name = "symlinkat";
	else if (num == __NR_readlinkat)
		syscall_name = "readlinkat";
	else if (num == __NR_fchmodat)
		syscall_name = "fchmodat";
	else if (num == __NR_faccessat)
		syscall_name = "faccessat";
	else if (num == __NR_pselect6)
		syscall_name = "pselect6";
	else if (num == __NR_ppoll)
		syscall_name = "ppoll";
	else if (num == __NR_unshare)
		syscall_name = "unshare";
	else if (num == __NR_set_robust_list)
		syscall_name = "set_robust_list";
	else if (num == __NR_get_robust_list)
		syscall_name = "get_robust_list";
	else if (num == __NR_splice)
		syscall_name = "splice";
	else if (num == __NR_tee)
		syscall_name = "tee";
	else if (num == __NR_sync_file_range)
		syscall_name = "sync_file_range";
	else if (num == __NR_vmsplice)
		syscall_name = "vmsplice";
	else if (num == __NR_move_pages)
		syscall_name = "move_pages";
	else if (num == __NR_utimensat)
		syscall_name = "utimensat";
	else if (num == __NR_epoll_pwait)
		syscall_name = "epoll_pwait";
	else if (num == __NR_signalfd)
		syscall_name = "signalfd";
	else if (num == __NR_timerfd_create)
		syscall_name = "timerfd_create";
	else if (num == __NR_eventfd)
		syscall_name = "eventfd";
	else if (num == __NR_fallocate)
		syscall_name = "fallocate";
	else if (num == __NR_timerfd_settime)
		syscall_name = "timerfd_settime";
	else if (num == __NR_timerfd_gettime)
		syscall_name = "timerfd_gettime";
	else if (num == __NR_accept4)
		syscall_name = "accept4";
	else if (num == __NR_signalfd4)
		syscall_name = "signalfd4";
	else if (num == __NR_eventfd2)
		syscall_name = "eventfd2";
	else if (num == __NR_epoll_create1)
		syscall_name = "epoll_create1";
	else if (num == __NR_dup3)
		syscall_name = "dup3";
	else if (num == __NR_pipe2)
		syscall_name = "pipe2";
	else if (num == __NR_inotify_init1)
		syscall_name = "inotify_init1";
	else if (num == __NR_preadv)
		syscall_name = "preadv";
	else if (num == __NR_pwritev)
		syscall_name = "pwritev";
	else if (num == __NR_rt_tgsigqueueinfo)
		syscall_name = "rt_tgsigqueueinfo";
	else if (num == __NR_perf_event_open)
		syscall_name = "perf_event_open";
	else if (num == __NR_recvmmsg)
		syscall_name = "recvmmsg";
	else if (num == __NR_fanotify_init)
		syscall_name = "fanotify_init";
	else if (num == __NR_fanotify_mark)
		syscall_name = "fanotify_mark";
	else if (num == __NR_prlimit64)
		syscall_name = "prlimit64";
	else if (num == __NR_name_to_handle_at)
		syscall_name = "name_to_handle_at";
	else if (num == __NR_open_by_handle_at)
		syscall_name = "open_by_handle_at";
	else if (num == __NR_clock_adjtime)
		syscall_name = "clock_adjtime";
	else if (num == __NR_syncfs)
		syscall_name = "syncfs";
	else if (num == __NR_sendmmsg)
		syscall_name = "sendmmsg";
	else if (num == __NR_setns)
		syscall_name = "setns";
	else if (num == __NR_getcpu)
		syscall_name = "getcpu";
	else if (num == __NR_process_vm_readv)
		syscall_name = "process_vm_readv";
	else if (num == __NR_process_vm_writev)
		syscall_name = "process_vm_writev";
	else if (num == __NR_kcmp)
		syscall_name = "kcmp";
	else if (num == __NR_finit_module)
		syscall_name = "finit_module";
	else if (num == __NR_sched_setattr)
		syscall_name = "sched_setattr";
	else if (num == __NR_sched_getattr)
		syscall_name = "sched_getattr";
	else if (num == __NR_renameat2)
		syscall_name = "renameat2";
	else if (num == __NR_seccomp)
		syscall_name = "seccomp";
	else if (num == __NR_getrandom)
		syscall_name = "getrandom";
	else if (num == __NR_memfd_create)
		syscall_name = "memfd_create";
	else if (num == __NR_kexec_file_load)
		syscall_name = "kexec_file_load";
	else if (num == __NR_bpf)
		syscall_name = "bpf";
	else if (num == __NR_execveat)
		syscall_name = "execveat";
	else if (num == __NR_userfaultfd)
		syscall_name = "userfaultfd";
	else if (num == __NR_membarrier)
		syscall_name = "membarrier";

	return syscall_name;

}
/////////////////////////////////////////////////////////////////////

#endif
