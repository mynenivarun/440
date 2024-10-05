#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/security.h>
#include <linux/binfmts.h>
#include <linux/fs.h>
#include <linux/debugfs.h>
#include <linux/string.h>
#include <linux/xattr.h>

#define SAMPLE_TRUSTED   0x00000001
#define SAMPLE_UNTRUSTED 0x00000002
#define SAMPLE_IGNORE    0x00000004
#define CWLITE_FLAG      0x80000000

#define XATTR_SAMPLE_SUFFIX "sample"
#define XATTR_NAME_SAMPLE XATTR_SECURITY_PREFIX XATTR_SAMPLE_SUFFIX

static struct dentry *cwl_debugfs_root;

static u32 get_inode_sid(struct inode *inode)
{
    char *buf;
    ssize_t ret;
    u32 sid = SAMPLE_UNTRUSTED;  // Default to untrusted

    buf = kmalloc(sizeof(u32), GFP_KERNEL);
    if (!buf)
        return SAMPLE_UNTRUSTED;

    ret = __vfs_getxattr(inode, inode->i_security, XATTR_NAME_SAMPLE, buf, sizeof(u32));
    if (ret == sizeof(u32))
        memcpy(&sid, buf, sizeof(u32));

    kfree(buf);
    return sid;
}

static int set_inode_sid(struct inode *inode, u32 sid)
{
    return __vfs_setxattr(inode, inode->i_security, XATTR_NAME_SAMPLE, &sid, sizeof(sid), 0);
}

static ssize_t cwlite_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    char tmp[2];
    int cwlite_value = ((u32)current->security & CWLITE_FLAG) ? 1 : 0;
    tmp[0] = cwlite_value + '0';
    tmp[1] = '\n';
    return simple_read_from_buffer(buf, count, ppos, tmp, 2);
}

static ssize_t cwlite_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char tmp[2];
    if (copy_from_user(tmp, buf, 1))
        return -EFAULT;

    switch(tmp[0]) {
    case '0':
        current->security = (void *)((u32)current->security & ~CWLITE_FLAG);
        break;
    case '1':
        current->security = (void *)((u32)current->security | CWLITE_FLAG);
        break;
    default:
        return -EINVAL;
    }
    return count;
}

static const struct file_operations cwlite_fops = {
    .read = cwlite_read,
    .write = cwlite_write,
};

static int has_perm(struct task_struct *task, struct inode *inode, int mask)
{
    u32 tsid = (u32)task->security;
    u32 isid = get_inode_sid(inode);
    
    if (tsid == SAMPLE_IGNORE || isid == SAMPLE_IGNORE)
        return 0;
    
    if (tsid == SAMPLE_TRUSTED && isid == SAMPLE_TRUSTED)
        return 0;
    
    if ((tsid & CWLITE_FLAG) && isid == SAMPLE_UNTRUSTED)
        return 0;
    
    printk(KERN_INFO "sample: Denied access: task=%d, inode=%lu, mask=%x\n", task->pid, inode->i_ino, mask);
    return -EACCES;
}

static int sample_inode_permission(struct inode *inode, int mask)
{
    return has_perm(current, inode, mask);
}

static int sample_bprm_set_security(struct linux_binprm *bprm)
{
    struct inode *inode = bprm->file->f_path.dentry->d_inode;
    u32 sid = get_inode_sid(inode);
    bprm->security = (void *)sid;
    return 0;
}

static int sample_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len)
{
    u32 sid = (u32)current->security;
    *name = XATTR_NAME_SAMPLE;
    *value = kmalloc(sizeof(u32), GFP_KERNEL);
    if (!*value)
        return -ENOMEM;
    *(u32 *)*value = sid;
    *len = sizeof(u32);
    return 0;
}

static int sample_inode_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
    if (strcmp(name, XATTR_NAME_SAMPLE) == 0) {
        if (size != sizeof(u32))
            return -EINVAL;
        return set_inode_sid(dentry->d_inode, *(u32 *)value);
    }
    return 0;
}

static int sample_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
    return set_inode_sid(dentry->d_inode, (u32)current->security);
}

static int sample_file_permission(struct file *file, int mask)
{
    return has_perm(current, file->f_path.dentry->d_inode, mask);
}

static struct security_operations sample_ops = {
    .inode_permission = sample_inode_permission,
    .bprm_set_security = sample_bprm_set_security,
    .inode_init_security = sample_inode_init_security,
    .inode_setxattr = sample_inode_setxattr,
    .inode_create = sample_inode_create,
    .file_permission = sample_file_permission,
};

static int __init sample_init(void)
{
    int ret;

    cwl_debugfs_root = debugfs_create_dir("cwl", NULL);
    if (!cwl_debugfs_root)
        return -ENOMEM;

    if (!debugfs_create_file("cwlite", 0644, cwl_debugfs_root, NULL, &cwlite_fops)) {
        debugfs_remove_recursive(cwl_debugfs_root);
        return -ENOMEM;
    }

    ret = register_security(&sample_ops);
    if (ret) {
        printk(KERN_ERR "CW-Lite LSM: Unable to register with kernel\n");
        debugfs_remove_recursive(cwl_debugfs_root);
        return ret;
    }

    printk(KERN_INFO "CW-Lite LSM initialized\n");
    return 0;
}

static void __exit sample_exit(void)
{
    debugfs_remove_recursive(cwl_debugfs_root);
    printk(KERN_INFO "CW-Lite LSM removed\n");
}

security_initcall(sample_init);
module_exit(sample_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("CW-Lite Linux Security Module");