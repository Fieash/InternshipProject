#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/stat.h>
#include <linux/kallsyms.h>

// declare functions here
void analyze_modules(void);
//extern unsigned long lookup_name(const char *);

static int __init modules_init(void)
{
    printk(KERN_INFO "==== Start module detection app ====\n");
    analyze_modules();
    return 0;
}

static void __exit modules_exit(void)
{
    printk(KERN_INFO "==== Exit module detection app ====\n");
}

void analyze_modules(void)
{
	struct kset *mod_kset;
	struct kobject *cur, *tmp;
	struct module_kobject *kobj;
	int counter = 0;

	mod_kset = (void *)kallsyms_lookup_name("module_kset");
	if (!mod_kset)
		return;

	list_for_each_entry_safe(cur, tmp, &mod_kset->list, entry)
	{
		if (!kobject_name(tmp))
			break;

		kobj = container_of(tmp, struct module_kobject, kobj);

		if (kobj && kobj->mod && kobj->mod->name)
		{
			mutex_lock(&module_mutex);

			if(!find_module(kobj->mod->name))
			{
				printk(KERN_ALERT "Module [%s] hidden.\n", kobj->mod->name);
				counter++;
			}

			mutex_unlock(&module_mutex);
		}
	}

	if (counter == 0) 
	{
		printk(KERN_ALERT "Result: No hidden modules found.\n");
	}
	else
	{
		printk(KERN_ALERT "Result: %d hidden module(s) found.\n", counter);
	}
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("WYZ");
MODULE_DESCRIPTION("rootkit detection program internship project");

module_init(modules_init);
module_exit(modules_exit);
