#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/sched.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/sched/signal.h>
#include <linux/kthread.h>
#include <linux/binfmts.h>
#include <linux/kmod.h> // For call_usermodehelper

static char *program_name = "/bin/bash"; // Default program name set to bash
module_param(program_name, charp, 0);
MODULE_PARM_DESC(program_name, "The name of the program to execute (default: /bin/bash)");

static struct kprobe kp = {
    .symbol_name = "do_fork",  // The function to probe
};

// Function to check if the file exists
static int file_exists(const char *filename) {
    struct path path;
    int err;

    err = kern_path(filename, LOOKUP_FOLLOW, &path);
    if (err) {
        printk(KERN_ERR "File %s does not exist\n", filename);
        return -ENOENT; // File does not exist
    }

    path_put(&path); // Release the path reference
    return 0; // File exists
}

// Thread function to execute the user-space program
static int thread_fn(void *data) {
    const char *const *argv = (const char *const *)data;

    // Call user mode helper to execute the program
    call_usermodehelper(argv[0], NULL, NULL, UMH_WAIT_PROC);
    
    return 0; // Return when done
}

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    // Declare variables at the beginning
    const char *const argv[] = {program_name, NULL}; // Arguments for the program
    struct task_struct *task;

    
    // Check if the specified program file exists
    if (file_exists(program_name) != 0) {
        return 0; // Exit if the file does not exist
    }

    
    // Fork a new kernel thread to execute the program
    task = kthread_run(thread_fn, (void *)argv, "exec_thread");
    if (IS_ERR(task)) {
        printk(KERN_ERR "Failed to create kernel thread for %s\n", program_name);
    } else {
        printk(KERN_INFO "Started kernel thread to execute %s with PID: %d\n", program_name, task->pid);
    }

    return 0;  // Continue execution
}

static int __init kprobe_init(void) {
    kp.pre_handler = handler_pre;  // Set the pre-handler
    register_kprobe(&kp);          // Register the probe
    printk(KERN_INFO "KProbe registered for %s\n", kp.symbol_name);
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp);  // Unregister the probe
    printk(KERN_INFO "KProbe unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
