#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <asm/asm-offsets.h> // to use NR_syscalls (number of system calls)


#define BETWEEN_PTR(x, y, z) ( \
	((uintptr_t)x >= (uintptr_t)y) && \
	((uintptr_t)x < ((uintptr_t)y+(uintptr_t)z)) \
)


// declare functions here
void analyze_syscalls(void);
const char *find_hidden_module(unsigned long addr);


static int __init syscalls_init(void)
{
    printk(KERN_INFO "==== Start syscall detection app.\n");
    analyze_syscalls();
    return 0;
}


static void __exit syscalls_exit(void)
{
    printk(KERN_INFO "==== Exit syscall detection app.\n");
}


// Detect modules in the syscall table that aren't within the core kernel text section
void analyze_syscalls(void){
	int i;
	const char *mod_name;
	unsigned long addr;
	struct module *mod;

    unsigned long *sct; 			// Syscall Table
    int (*ckt)(unsigned long addr); // Core Kernel Text

	sct = (void *)kallsyms_lookup_name("sys_call_table");
	ckt = (void *)kallsyms_lookup_name("core_kernel_text");

	if (!sct || !ckt)
		return;

	for (i = 0; i < NR_syscalls; i++){
		addr = sct[i];
		if (!ckt(addr)){
			mutex_lock(&module_mutex);
			mod = __module_address(addr);
			if (mod){
				printk(KERN_ALERT "Module [%s] hooked syscall [%d].\n", mod->name, i);
			} else {
				mod_name = find_hidden_module(addr);
				if (mod_name)
					printk(KERN_ALERT "Hidden module [%s] hooked syscall [%d].\n", mod_name, i);
			}
			mutex_unlock(&module_mutex);
		}
	}
}


// Used by analyze_syscalls() to return the name of the hidden module given their address
const char *find_hidden_module(unsigned long addr){
	const char *mod_name = NULL;
	struct kset *mod_kset;
	struct kobject *cur, *tmp;
	struct module_kobject *kobj;

	mod_kset = (void *)kallsyms_lookup_name("module_kset");
	if (!mod_kset)
		return NULL;

	list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry){
		if (!kobject_name(tmp))
			break;

		kobj = container_of(tmp, struct module_kobject, kobj);
		if (!kobj || !kobj->mod)
			continue;

#if (LINUX_VERSION_CODE >= KERNEL_VERSION(4,4,0))
		if (BETWEEN_PTR(addr, kobj->mod->core_layout.base, kobj->mod->core_layout.size)){
			mod_name = kobj->mod->name;
		}
#else
		if (BETWEEN_PTR(addr, kobj->mod->module_core, kobj->mod->core_size)){
			mod_name = kobj->mod->name;
		}
#endif
	}

	return mod_name;
}


MODULE_LICENSE("GPL");
MODULE_AUTHOR("WYZ");
MODULE_DESCRIPTION("rootkit detection program internship project");

module_init(syscalls_init);
module_exit(syscalls_exit);