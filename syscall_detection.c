#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/asm-offsets.h> // NR_syscalls (number of system calls)

#define BETWEEN_PTR(a, b, c) (	((uintptr_t)b <= (uintptr_t)a) && ((uintptr_t)a < ((uintptr_t)b+(uintptr_t)c))	)


// syscall array definition
//const int syscall_numbers[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 135, 136, 137, 138, 139, 140, 141, 142, 143, 144, 145, 146, 147, 148, 149, 150, 151, 152, 153, 154, 155, 156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173, 174, 175, 176, 177, 178, 179, 180, 181, 182, 183, 184, 185, 186, 187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199, 200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238, 239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 262, 263, 264, 265, 266, 267, 268, 269, 270, 271, 272, 273, 274, 275, 276, 277, 278, 279, 280, 281, 282, 283, 284, 285, 286, 287, 288, 289, 290, 291, 292, 293, 294, 295, 296, 297, 298, 299, 300, 301, 302, 303, 304, 305, 306, 307, 308, 309, 310, 311, 312, 313, 314, 315, 316, 317, 318, 319, 320, 321, 322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 332};
const char* syscall_names[] = {"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind", "listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid", "getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget", "capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality", "ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler", "sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall", "munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct", "settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module", "init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall", "security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr", "flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity", "set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create", "epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64", "timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres", "clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key", "keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat", "mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat", "pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages", "utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4", "signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev", "rt_tgsigqueueinfo", "perf_event_open", "recvmmsg", "fanotify_init", "fanotify_mark", "prlimit64", "name_to_handle_at", "open_by_handle_at", "clock_adjtime", "syncfs", "sendmmsg", "setns", "getcpu", "process_vm_readv", "process_vm_writev", "kcmp", "finit_module", "sched_setattr", "sched_getattr", "renameat2", "seccomp", "getrandom", "memfd_create", "kexec_file_load", "bpf", "execveat", "userfaultfd", "membarrier", "mlock2", "copy_file_range", "preadv2", "pwritev2", "pkey_mprotect", "pkey_alloc", "pkey_free", "statx"};


// suspicious syscalls



// declare functions here
void analyze_syscalls(void);
const char *find_hidden_module(unsigned long address);


static int __init syscalls_init(void)
{
    printk(KERN_INFO "==== Start syscall hook detection app ====\n");
    analyze_syscalls();
    return 0;
}


static void __exit syscalls_exit(void)
{
    printk(KERN_INFO "==== Exit syscall hook detection app ====\n");
}


// Detect modules in the syscall table that aren't within the core kernel text section
void analyze_syscalls(void)
{
	int i;
	const char *module_name;
	unsigned long address;
	struct module *module;
	int counter = 0;

    unsigned long *sct; 			// Syscall Table
    int (*ckt)(unsigned long address); // Core Kernel Text

	sct = (void *)kallsyms_lookup_name("sys_call_table");
	ckt = (void *)kallsyms_lookup_name("core_kernel_text");

	if (!sct || !ckt)
		return;

	for (i = 0; i < NR_syscalls; i++)
	{
		address = sct[i];
		if (!ckt(address))
		{
			mutex_lock(&module_mutex);
			module = __module_address(address);
			if (module)
			{
				// suspicious file syscalls ("access", "close", "fchmod", "fchown", "fstat", "lseek", "open", "read", "statfs", "write", "getdents", "getdents64")
				if(	(strcmp(syscall_names[i], "access")) == 0 || (strcmp(syscall_names[i], "close")) == 0 || (strcmp(syscall_names[i], "fchmod")) == 0   || (strcmp(syscall_names[i], "fchown")) == 0 || \
					(strcmp(syscall_names[i], "fstat")) == 0  || (strcmp(syscall_names[i], "lseek")) == 0 || (strcmp(syscall_names[i], "open")) == 0     || (strcmp(syscall_names[i], "read")) == 0   || \
					(strcmp(syscall_names[i], "statfs")) == 0 || (strcmp(syscall_names[i], "write")) == 0 || (strcmp(syscall_names[i], "getdents")) == 0 || (strcmp(syscall_names[i], "getdents64")) == 0 )
				{
					printk(KERN_ALERT "Module [%s] hooked syscall [%d] [%s] - suspicious file activity\n", module->name, i, syscall_names[i]);
				}

				// suspicious network syscalls ("bind", "listen", "socket", "setsockopt", "accept", "connect", "send", "sendto", "sendmsg")
				if(	(strcmp(syscall_names[i], "bind")) == 0    || (strcmp(syscall_names[i], "listen")) == 0  || (strcmp(syscall_names[i], "socket")) == 0 || (strcmp(syscall_names[i], "setsockopt")) == 0  || \
					(strcmp(syscall_names[i], "accept")) == 0  || (strcmp(syscall_names[i], "connect")) == 0 || (strcmp(syscall_names[i], "send")) == 0   || (strcmp(syscall_names[i], "sendto")) == 0		|| \
					(strcmp(syscall_names[i], "sendmsg")) == 0 )
				{
					printk(KERN_ALERT "Module [%s] hooked syscall [%d] [%s] - suspicious network activity\n", module->name, i, syscall_names[i]);
				}
					
				// suspicious memory syscalls ("mmap", "munmap")
				if(	(strcmp(syscall_names[i], "mmap")) == 0 || (strcmp(syscall_names[i], "munmap")) == 0 )
				{
					printk(KERN_ALERT "Module [%s] hooked syscall [%d] [%s] - suspicious memory activity\n", module->name, i, syscall_names[i]);
				}

				// suspicious process syscalls ("kill", "execve", "fork")
				if(	(strcmp(syscall_names[i], "kill")) == 0 || (strcmp(syscall_names[i], "execve")) == 0 || (strcmp(syscall_names[i], "fork")) == 0 )
				{
					printk(KERN_ALERT "Module [%s] hooked syscall [%d] [%s] - suspicious process activity\n", module->name, i, syscall_names[i]);
				}

				counter++;
			} 
			else 
			{
				module_name = find_hidden_module(address);
				if (module_name)
				{
					// suspicious file syscalls ("access", "close", "fchmod", "fchown", "fstat", "lseek", "open", "read", "statfs", "write", "getdents", "getdents64")
					if(	(strcmp(syscall_names[i], "access")) == 0 || (strcmp(syscall_names[i], "close")) == 0 || (strcmp(syscall_names[i], "fchmod")) == 0   || (strcmp(syscall_names[i], "fchown")) == 0  || \
						(strcmp(syscall_names[i], "fstat")) == 0  || (strcmp(syscall_names[i], "lseek")) == 0 || (strcmp(syscall_names[i], "open")) == 0     || (strcmp(syscall_names[i], "read")) == 0    || \
						(strcmp(syscall_names[i], "statfs")) == 0 || (strcmp(syscall_names[i], "write")) == 0 || (strcmp(syscall_names[i], "getdents")) == 0 || (strcmp(syscall_names[i], "getdents64")) == 0 )
					{
						printk(KERN_ALERT "Hidden module [%s] hooked syscall [%d] [%s] - suspicious file activity\n", module_name, i, syscall_names[i]);
					}

					// suspicious network syscalls ("bind", "listen", "socket", "setsockopt", "accept", "connect", "send", "sendto", "sendmsg")
					if(	(strcmp(syscall_names[i], "bind")) == 0    || (strcmp(syscall_names[i], "listen")) == 0  || (strcmp(syscall_names[i], "socket")) == 0 || (strcmp(syscall_names[i], "setsockopt")) == 0  || \
						(strcmp(syscall_names[i], "accept")) == 0  || (strcmp(syscall_names[i], "connect")) == 0 || (strcmp(syscall_names[i], "send")) == 0   || (strcmp(syscall_names[i], "sendto")) == 0      || \
						(strcmp(syscall_names[i], "sendmsg")) == 0 )
					{
						printk(KERN_ALERT "Hidden module [%s] hooked syscall [%d] [%s] - suspicious network activity\n", module_name, i, syscall_names[i]);
					}
						
					// suspicious memory syscalls ("mmap", "munmap")
					if(	(strcmp(syscall_names[i], "mmap")) == 0 || (strcmp(syscall_names[i], "munmap")) == 0 )
					{
						printk(KERN_ALERT "Hidden module [%s] hooked syscall [%d] [%s] - suspicious memory activity\n", module_name, i, syscall_names[i]);
					}

					// suspicious process syscalls ("kill", "execve", "fork")
					if(	(strcmp(syscall_names[i], "kill")) == 0 || (strcmp(syscall_names[i], "execve")) == 0 || (strcmp(syscall_names[i], "fork")) == 0 )
					{
						printk(KERN_ALERT "Hidden module [%s] hooked syscall [%d] [%s] - suspicious process activity\n", module_name, i, syscall_names[i]);
					}
					
					counter++;
				}
			}
			mutex_unlock(&module_mutex);
		}
	}

	if (counter == 0) 
	{
		printk(KERN_ALERT "Result: No hooked syscalls found.\n");
	}
	else
	{
		printk(KERN_ALERT "Result: %d hooked syscall(s) found.\n", counter);
	}
}


// Return the name of a (hidden) module given its address
const char *find_hidden_module(unsigned long address)
{
	const char *module_name = NULL;
	struct kset *module_kset;
	struct kobject *cur, *tmp;
	struct module_kobject *kobj;

	module_kset = (void *)kallsyms_lookup_name("module_kset");
	if (!module_kset)
		return NULL;

	list_for_each_entry_safe(cur, tmp, &module_kset->list, entry)
	{
		if (!kobject_name(tmp))
			break;

		kobj = container_of(tmp, struct module_kobject, kobj);
		if (!kobj || !kobj->mod)
			continue;

		#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
				if (BETWEEN_PTR(address, kobj->mod->core_layout.base, kobj->mod->core_layout.size))
				{
					module_name = kobj->mod->name;
				}
		#else
				if (BETWEEN_PTR(address, kobj->mod->module_core, kobj->mod->core_size))
				{
					module_name = kobj->mod->name;
				}
		#endif 
	}

	return module_name;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("WYZ");
MODULE_DESCRIPTION("rootkit detection program internship project");

module_init(syscalls_init);
module_exit(syscalls_exit);