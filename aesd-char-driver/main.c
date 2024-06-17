/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/types.h>
#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/slab.h> //kmalloc, krealloc, kfree
#include "aesdchar.h"
#include "aesd_ioctl.h"
int aesd_major =   0; // use dynamic major
int aesd_minor =   0;

MODULE_AUTHOR("Zixuan Ding");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp)
{
    struct aesd_dev *dev;
    PDEBUG("open");

    dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
    filp->private_data = dev;
    
    return 0;
}

int aesd_release(struct inode *inode, struct file *filp)
{
    PDEBUG("release");
    //No actions for aesd_char device
    return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
    struct aesd_buffer_entry *tempEntry;
    size_t entryOffset;
    ssize_t retval = 0;
    //uint8_t i;

    PDEBUG("read %zu bytes with offset %lld",count,*f_pos);
    
    down_read(&(aesd_device.cBufferSem)); //lock device
/*    
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED ; i++)
    {
        PDEBUG("cBuffer[%u], size: %zu = %s", i, aesd_device.cBuffer.entry[i].size, aesd_device.cBuffer.entry[i].buffptr);
    }
*/
    tempEntry = aesd_circular_buffer_find_entry_offset_for_fpos(&(aesd_device.cBuffer), (size_t)*f_pos, &entryOffset);
    
    if (tempEntry != NULL)
    {
        retval = tempEntry->size - entryOffset;
        if (retval > count) retval = count;
        if (copy_to_user(buf, tempEntry->buffptr + entryOffset, (unsigned long)retval))
        {
            retval = -EFAULT;
            PDEBUG("ERROR: copy_to_user failed\n");
            goto aesd_read_exit;
        }
        *f_pos += (loff_t)retval;
    }

aesd_read_exit:
    up_read(&(aesd_device.cBufferSem)); //unlock device

    return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
    size_t i;
    ssize_t retval = -ENOMEM;
    bool lineCompleted = false;
    struct aesd_buffer_entry newEntry;

    PDEBUG("write %zu bytes with offset %lld",count,*f_pos);

    down_write(&(aesd_device.cBufferSem)); //lock device
    
    aesd_device.tempBuffer = (char *)krealloc((void *)aesd_device.tempBuffer, (count + aesd_device.tempBufferSize), GFP_KERNEL);
    
    if (copy_from_user(aesd_device.tempBuffer + aesd_device.tempBufferSize, buf, (unsigned long) count))
    {
        retval = -EFAULT;
        PDEBUG("ERROR: copy_from_user failed\n");
        goto aesd_write_exit;
    }
    
    for (i = aesd_device.tempBufferSize; i < (count + aesd_device.tempBufferSize); i++)
    {
        if (aesd_device.tempBuffer[i] == '\n')
        {
            lineCompleted = true;
            break;
        }
    }
    retval = i - aesd_device.tempBufferSize;
    aesd_device.tempBufferSize = i;
    
    if (lineCompleted)
    {
        retval++;
        aesd_device.tempBufferSize++;
    
        newEntry.buffptr = aesd_device.tempBuffer;
        newEntry.size = aesd_device.tempBufferSize;
        
        if (aesd_device.cBuffer.full)
        {
            if (aesd_device.cBuffer.entry[aesd_device.cBuffer.out_offs].buffptr != NULL)
            {
                kfree(aesd_device.cBuffer.entry[aesd_device.cBuffer.out_offs].buffptr);
                aesd_device.cBuffer.entry[aesd_device.cBuffer.out_offs].buffptr = NULL;
            }
        }
        aesd_circular_buffer_add_entry(&(aesd_device.cBuffer), &newEntry);
        
        aesd_device.tempBuffer = NULL;
        aesd_device.tempBufferSize = 0;
    }

aesd_write_exit:
    up_write(&(aesd_device.cBufferSem)); //unlock device

    return retval;
}

loff_t aesd_llseek(struct file *filp, loff_t off, int whence)
{
    uint8_t i;
    size_t totalSize = 0;
    loff_t retval;

    down_write(&(aesd_device.cBufferSem)); //lock device
    
    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED ; i++)
    {
        if (aesd_device.cBuffer.entry[i].buffptr != NULL)
        {
            totalSize += aesd_device.cBuffer.entry[i].size;
        }
    }
    
    retval = fixed_size_llseek(filp, off, whence, (loff_t)totalSize);
    PDEBUG("llseek: total size=%ld, offset=%lld, retval=%lld.", totalSize, off, retval);
    
    up_write(&(aesd_device.cBufferSem)); //unlock device
    
    return retval;
}

long aesd_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int retval = 0;
    struct aesd_seekto seekto;
    uint8_t numOfEntries = 0, i, opBufferIndex;
    long file_offset = 0;
    
	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if (_IOC_TYPE(cmd) != AESD_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > AESDCHAR_IOC_MAXNR) return -ENOTTY;

	switch(cmd) {

	    case AESDCHAR_IOCSEEKTO:
	        if (copy_from_user(&seekto, (const void __user *)arg, sizeof(seekto)) != 0)
	        {
	            retval = -EFAULT;
	            goto aesd_ioctl_exit;
	        }
	        else
	        {
	            down_write(&(aesd_device.cBufferSem)); //lock device

	            if (aesd_device.cBuffer.full)
	            {
	                numOfEntries = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	            }
	            else
	            {
	                numOfEntries = aesd_device.cBuffer.in_offs - aesd_device.cBuffer.out_offs;
	            }
	            
	            if ((seekto.write_cmd) < 0 || (seekto.write_cmd >= numOfEntries))
	            {
	                PDEBUG("ioctl AESDCHAR_IOCSEEKTO: number of commands:%d NOT fit buffer size:%d", seekto.write_cmd, numOfEntries);
	                retval = -EINVAL;
	                goto aesd_ioctl_unlock_exit;
	            }
	            
	            for (i = 0; i < seekto.write_cmd; i++)
	            {
	                opBufferIndex = aesd_device.cBuffer.out_offs + i;
	                if (opBufferIndex >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
	                {
	                    opBufferIndex -= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	                }
	                
	                file_offset += aesd_device.cBuffer.entry[opBufferIndex].size;
	            }
	            
	            opBufferIndex = aesd_device.cBuffer.out_offs + seekto.write_cmd;
	            if (opBufferIndex >= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED)
	            {
	                opBufferIndex -= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
	            }
	            if ((seekto.write_cmd_offset < 0) || (seekto.write_cmd_offset >= aesd_device.cBuffer.entry[opBufferIndex].size))
	            {
	                PDEBUG("ioctl AESDCHAR_IOCSEEKTO: command offset:%d NOT fit buffer entry size:%ld", seekto.write_cmd_offset, aesd_device.cBuffer.entry[opBufferIndex].size);
	                retval = -EINVAL;
	                goto aesd_ioctl_unlock_exit;
	            }
	            
	            file_offset += seekto.write_cmd_offset;
	            
	            filp->f_pos = file_offset;
	            retval = file_offset;
	            goto aesd_ioctl_unlock_exit;
	        }
		break;


	    default:  /* redundant, as cmd was checked against MAXNR */
		    return -ENOTTY;
	}
aesd_ioctl_unlock_exit:
    up_write(&(aesd_device.cBufferSem)); //unlock device
aesd_ioctl_exit:
	return retval;

}

struct file_operations aesd_fops = {
    .owner          = THIS_MODULE,
    .read           = aesd_read,
    .write          = aesd_write,
    .open           = aesd_open,
    .release        = aesd_release,
   	.llseek         = aesd_llseek,
    .unlocked_ioctl = aesd_ioctl,
};

static int aesd_setup_cdev(struct aesd_dev *dev)
{
    int err, devno = MKDEV(aesd_major, aesd_minor);

    cdev_init(&dev->cdev, &aesd_fops);
    dev->cdev.owner = THIS_MODULE;
    dev->cdev.ops = &aesd_fops;
    err = cdev_add (&dev->cdev, devno, 1);
    if (err) {
        printk(KERN_ERR "Error %d adding aesd cdev", err);
    }
    return err;
}



int aesd_init_module(void)
{
    dev_t dev = 0;
    int result;
    result = alloc_chrdev_region(&dev, aesd_minor, 1,
            "aesdchar");
    aesd_major = MAJOR(dev);
    if (result < 0) {
        printk(KERN_WARNING "Can't get major %d\n", aesd_major);
        return result;
    }
    memset(&aesd_device,0,sizeof(struct aesd_dev));
    aesd_circular_buffer_init(&(aesd_device.cBuffer)); //init circular buffer
    init_rwsem(&(aesd_device.cBufferSem)); //init rw semaphore for circular buffer

    result = aesd_setup_cdev(&aesd_device);

    if( result ) {
        unregister_chrdev_region(dev, 1);
    }
    return result;

}

void aesd_cleanup_module(void)
{
    uint8_t i;

    dev_t devno = MKDEV(aesd_major, aesd_minor);

    cdev_del(&aesd_device.cdev);

    for (i = 0; i < AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED ; i++)
    {
        if (aesd_device.cBuffer.entry[i].buffptr != NULL)
        {
            kfree(aesd_device.cBuffer.entry[i].buffptr);
            aesd_device.cBuffer.entry[i].buffptr = NULL;
        }
    }
    
    if (aesd_device.tempBuffer != NULL)
    {
        kfree(aesd_device.tempBuffer);
        aesd_device.tempBuffer = NULL;
    }
    aesd_device.tempBufferSize = 0;

    unregister_chrdev_region(devno, 1);
}



module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
