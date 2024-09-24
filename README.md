<--EXAMPLE CODE THAT COULD RUN-->

#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/kernel.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/sched/signal.h>

static struct kprobe kp_copy_from_user;
static struct kprobe kp_copy_to_user;

// Function to kill a process
void kill_process(pid_t pid) {
    struct task_struct *task;

    // Find the task by PID
    task = pid_task(find_vpid(pid), PIDTYPE_PID);
    if (task) {
        // Send SIGKILL to the process
        send_sig(SIGKILL, task, 1);
        printk(KERN_INFO "Killed process with PID: %d\n", pid);
    } else {
        printk(KERN_ERR "Process with PID: %d not found\n", pid);
    }
}

// Function to check if an address is in a protected region
bool is_address_protected(void *addr, struct mm_struct *mm) {
    struct vm_area_struct *vma;

    down_read(&mm->mmap_sem); // Acquire read lock on the mmap semaphore
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
        // Check if the address is within the range of this VMA
        if (addr >= (void *)vma->vm_start && addr < (void *)vma->vm_end) {
            // Example: Check if the VMA is in a protected range
            if (vma->vm_flags & VM_EXEC) { // Example condition: executable memory
                up_read(&mm->mmap_sem); // Release the lock
                return true; // Address is in a protected region
            }
        }
    }
    up_read(&mm->mmap_sem); // Release the lock
    return false; // Address is not in a protected region
}

// Pre-handler for copy_from_user
static int handler_pre_copy_from_user(struct kprobe *p, struct pt_regs *regs) {
    pid_t pid = current->pid; // Get the current process ID
    void __user *from = (void __user *)regs->si; // Source address

    // Check if the address is in a protected region
    if (is_address_protected((void *)from, current->mm)) {
        printk(KERN_WARNING "Hostile access detected from PID: %d to protected address: %p\n", pid, from);
        kill_process(pid); // Kill the hostile process
    }

    return 0; // Continue execution
}

// Pre-handler for copy_to_user
static int handler_pre_copy_to_user(struct kprobe *p, struct pt_regs *regs) {
    pid_t pid = current->pid; // Get the current process ID
    void __user *to = (void __user *)regs->di; // Destination address

    // Check if the address is in a protected region
    if (is_address_protected((void *)to, current->mm)) {
        printk(KERN_WARNING "Hostile access detected from PID: %d to protected address: %p\n", pid, to);
        kill_process(pid); // Kill the hostile process
    }

    return 0; // Continue execution
}

static int __init kprobe_init(void) {
    // Set up kprobes
    kp_copy_from_user.symbol_name = "copy_from_user";
    kp_copy_from_user.pre_handler = handler_pre_copy_from_user;

    kp_copy_to_user.symbol_name = "copy_to_user";
    kp_copy_to_user.pre_handler = handler_pre_copy_to_user;

    register_kprobe(&kp_copy_from_user);
    register_kprobe(&kp_copy_to_user);

    printk(KERN_INFO "KProbes registered for copy_from_user and copy_to_user\n");
    return 0;
}

static void __exit kprobe_exit(void) {
    unregister_kprobe(&kp_copy_from_user);
    unregister_kprobe(&kp_copy_to_user);
    printk(KERN_INFO "KProbes unregistered\n");
}

module_init(kprobe_init);
module_exit(kprobe_exit);
MODULE_LICENSE("GPL");
