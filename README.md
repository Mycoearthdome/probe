```c
#include <linux/kprobes.h>
#include <linux/module.h>

// Define the function that will be called when the kprobe is triggered
int change_strict_devmem(struct kprobe *p, struct pt_regs *regs)
{
    // Get the address of strict_devmem
    unsigned long addr = (unsigned long)&strict_devmem;

    // Change the value of strict_devmem
    *(bool *)addr = true; // or false

    return 0;
}

// Define the kprobe
static struct kprobe kp = {
    .addr = (kprobe_opcode_t *)kallsyms_lookup_name("strict_devmem"),
};

// Initialize the kprobe
static int __init kprobe_init(void)
{
    int ret;

    // Register the kprobe
    ret = register_kprobe(&kp);
    if (ret < 0) {
        printk(KERN_INFO "register_kprobe failed, returned %d\n", ret);
        return ret;
    }

    // Set the pre_handler to our function
    kp.pre_handler = change_strict_devmem;

    return 0;
}

// Cleanup the kprobe
static void __exit kprobe_exit(void)
{
    unregister_kprobe(&kp);
}

module_init(kprobe_init);
module_exit(kprobe_exit);
