#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/device.h>
#include <linux/cdev.h>

static int major_number;
static struct class *linsec_class;
static struct cdev linsec_cdev;
#define DEVICE_NAME "linsec"
#define IOCTL_SET_VALUE_A _IOW('a', 1, char *)
#define IOCTL_SET_VALUE_B _IOW('b', 2, char *)
#define IOCTL_SET_VALUE_C _IOW('c', 3, char *)
#define IOCTL_SET_VALUE_D _IOW('d', 4, char *)


static long device_ioctl(struct file *filep, unsigned int cmd, unsigned long arg) {
    int ret;
    char filename[256];
    switch (cmd) {
    case IOCTL_SET_VALUE_A:
        if (copy_from_user(filename, (char *)arg, sizeof(filename))) {
            pr_err("Failed to copy string from user space\n");
            return -EFAULT;
        }
        filename[sizeof(filename) - 1] = '\0';

        printk("[LINSEC] NEW FILE CREATED: %s", filename);
        break;
    case IOCTL_SET_VALUE_B:
        if (copy_from_user(filename, (char *)arg, sizeof(filename))) {
            pr_err("Failed to copy string from user space\n");
            return -EFAULT;
        }
        filename[sizeof(filename) - 1] = '\0';

        printk("[LINSEC] MALWARE DETECTED - STATIC ANALYSIS : %s", filename);
        break;
    
    case IOCTL_SET_VALUE_C:
        if (copy_from_user(filename, (char *)arg, sizeof(filename))) {
            pr_err("Failed to copy string from user space\n");
            return -EFAULT;
        }
        filename[sizeof(filename) - 1] = '\0';

        printk("[LINSEC] MALWARE DETECTED - DYNAMIC ANALYSIS : %s", filename);
        break;
    case IOCTL_SET_VALUE_D:
        if (copy_from_user(filename, (char *)arg, sizeof(filename))) {
            pr_err("Failed to copy string from user space\n");
            return -EFAULT;
        }
        filename[sizeof(filename) - 1] = '\0';

        printk("[LINSEC] New file %s is safe to execute.", filename);
        break;

    default:
        pr_err("Invalid IOCTL command\n");
        return -EINVAL;
    }

    return 0;
}

// File operations structure
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = device_ioctl,
};

static int __init ioctl_example_init(void) {
    int ret;  // Add a variable to store return values for error checking

    pr_info("[LINSEC] Initializing module\n");

    major_number = register_chrdev(0, DEVICE_NAME, &fops);
    if (major_number < 0) {
        pr_err("Failed to register device\n");
        return major_number;
    }
    pr_info("Registered character device with major number %d\n", major_number);

    linsec_class = class_create(DEVICE_NAME);
    if (IS_ERR(linsec_class)) {
        pr_err("Failed to create class\n");
        unregister_chrdev(major_number, DEVICE_NAME);
        return PTR_ERR(linsec_class);
    }

    if (device_create(linsec_class, NULL, MKDEV(major_number, 0), NULL, DEVICE_NAME) == NULL) {
        pr_err("Failed to create device file\n");
        class_destroy(linsec_class);
        unregister_chrdev(major_number, DEVICE_NAME);
        return -1;
    }

    pr_info("Device file /dev/%s created\n", DEVICE_NAME);

    return 0;
}

static void __exit ioctl_example_exit(void) {
    device_destroy(linsec_class, MKDEV(major_number, 0));
    class_destroy(linsec_class);
    unregister_chrdev(major_number, DEVICE_NAME);
    pr_info("[LINSEC] Module removed\n");
}

module_init(ioctl_example_init);
module_exit(ioctl_example_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("GROUP-11");
MODULE_DESCRIPTION("LINSEC MAIN MODEL");
MODULE_VERSION("0.1");