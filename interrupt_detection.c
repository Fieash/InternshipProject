#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/kallsyms.h>

#define BETWEEN_PTR(a, b, c) (	((uintptr_t)b <= (uintptr_t)a) && ((uintptr_t)a < ((uintptr_t)b+(uintptr_t)c))	)


// declare functions here
void analyze_interrupts(void);
const char *find_hidden_module(unsigned long address);


static int __init interrupts_init(void)
{
    printk(KERN_INFO "==== Start interrupt hook detection app ====\n");
	analyze_interrupts();
    return 0;
}


static void __exit interrupts_exit(void)
{
    printk(KERN_INFO "==== Exit interrupt hook detection app ====\n");
}


// Detect interrupt handlers in the interrupt discriptor table that aren't within the core kernel text section
void analyze_interrupts(void)
{
	int i;
	const char *module_name;
	unsigned long address;
	struct module *module;
	int counter = 0;

    unsigned long *idt; 			// Interrupt Discriptor Table
    int (*ckt)(unsigned long address); // Core Kernel Text

	idt = (void *)kallsyms_lookup_name("idt_table");
	ckt = (void *)kallsyms_lookup_name("core_kernel_text");

	if (!idt || !ckt)
		return;

	for (i = 0; i < 256; i++)
	{
		address = idt[i];
		if (!ckt(address))
		{
			mutex_lock(&module_mutex);
			module = __module_address(address);
			if (module)
			{
				printk(KERN_ALERT "Module [%s] hooked interrupt [%d].\n", module->name, i);
				counter++;
			} 
			else 
			{
				module_name = find_hidden_module(address);
				if (module_name)
				{
					printk(KERN_ALERT "Hidden module [%s] hooked interrupt [%d].\n", module_name, i);
					counter++;	
				}
			}
			mutex_unlock(&module_mutex);
		}
	}

	if (counter == 0) 
	{
		printk(KERN_ALERT "Result: No hooked interrupts found.\n");
	}
	else
	{
		printk(KERN_ALERT "Result: %d hooked interrupt(s) found.\n", counter);
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

module_init(interrupts_init);
module_exit(interrupts_exit);