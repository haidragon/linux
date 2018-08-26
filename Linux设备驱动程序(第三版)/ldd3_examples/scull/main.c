/*
 * main.c -- the bare scull char module
 *
 * 此代码为ldd3例子，自己加了些注释;希望可以和更多有着同样兴趣的鸟儿们一块学习讨论。
 * 哪有注释的不对的地方请发mail给我，或留言；
 *
 * author : liyangth@gmail.com 
 *
 * date: 2007-2-7
 * 
 * Note：注释的每一个关键的段都以[tag00]作了标签，大家可以按照tag的顺序阅读；
 * e.g: 搜索 "Tag000"
 */

#include <linux/config.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>

#include <linux/kernel.h>	/* printk() */
#include <linux/slab.h>		/* kmalloc() */
#include <linux/fs.h>		/* everything... */
#include <linux/errno.h>	/* error codes */
#include <linux/types.h>	/* size_t */
#include <linux/proc_fs.h>
#include <linux/fcntl.h>	/* O_ACCMODE */
#include <linux/seq_file.h>
#include <linux/cdev.h>

#include <asm/system.h>		/* cli(), *_flags */
#include <asm/uaccess.h>	/* copy_*_user */

#include "scull.h"		/* local definitions */

/*
 * Our parameters which can be set at load time.
 */

int scull_major =   SCULL_MAJOR;
int scull_minor =   0;
int scull_nr_devs = SCULL_NR_DEVS;	/* number of bare scull devices */
int scull_quantum = SCULL_QUANTUM;
int scull_qset =    SCULL_QSET;

/*
 * 模块参数，可在模块转载时赋值，很灵活方便；
 * e.g:
 * 		insmod scull.ko scull_major=111 scull_nr_devs=3 scull_quantum=1000
 *
 *[形参说明]
 * 1 -- 变量名；
 * 2 -- 变量类型；
 * 3 -- sysfs入口项的访问许可掩码（一般用S_IRUGO就成）；
*/
module_param(scull_major, int, S_IRUGO); 
module_param(scull_nr_devs, int, S_IRUGO);
module_param(scull_quantum, int, S_IRUGO);
module_param(scull_qset, int, S_IRUGO);

MODULE_AUTHOR("Alessandro Rubini, Jonathan Corbet");
MODULE_LICENSE("Dual BSD/GPL");

struct scull_dev *scull_devices;	/* allocated in scull_init_module */
/* Note: 不要把它理解成一个指向scull_dev结构的指针, 它其实是一个scull_dev结构数组,等待下面kmalloc分配多个我们scull设备空间 */


/*
 * Empty out the scull device; 就像销毁链表,和理解如何编写一个字符驱动没有关系,可以不看;
 *
 * must be called with the device semaphore held. 要注意一下了,肯定是要同步的;
 *
 */
int scull_trim(struct scull_dev *dev)
{
	struct scull_qset *next, *dptr;
	int qset = dev->qset;   /* "dev" is not-null */
	int i;

	for (dptr = dev->data; dptr; dptr = next) { /* all the list items */
		if (dptr->data) {
			for (i = 0; i < qset; i++)
				kfree(dptr->data[i]);
			kfree(dptr->data);
			dptr->data = NULL;
		}
		next = dptr->next;
		kfree(dptr);
	}
	dev->size = 0;
	dev->quantum = scull_quantum;
	dev->qset = scull_qset;
	dev->data = NULL;
	return 0;
}

//Start: [Tag003] proc的实现,可以先不看;
#ifdef SCULL_DEBUG /* use proc only if debugging */
//这个是老方法实现的proc
/*
 * The proc filesystem: function to read and entry
 */

int scull_read_procmem(char *buf, char **start, off_t offset,
                   int count, int *eof, void *data)
{
	int i, j, len = 0;
	int limit = count - 80; /* Don't print more than this */

	for (i = 0; i < scull_nr_devs && len <= limit; i++) {
		struct scull_dev *d = &scull_devices[i];
		struct scull_qset *qs = d->data;
		if (down_interruptible(&d->sem))
			return -ERESTARTSYS;
		len += sprintf(buf+len,"\nDevice %i: qset %i, q %i, sz %li\n",
				i, d->qset, d->quantum, d->size);
		for (; qs && len <= limit; qs = qs->next) { /* scan the list */
			len += sprintf(buf + len, "  item at %p, qset at %p\n",
					qs, qs->data);
			if (qs->data && !qs->next) /* dump only the last item */
				for (j = 0; j < d->qset; j++) {
					if (qs->data[j])
						len += sprintf(buf + len,
								"    % 4i: %8p\n",
								j, qs->data[j]);
				}
		}
		up(&scull_devices[i].sem);
	}
	*eof = 1;
	return len;
}

//下面的是用新方法实现的
/*
 * For now, the seq_file implementation will exist in parallel.  The
 * older read_procmem function should maybe go away, though.
 */

/*
 * Here are our sequence iteration methods.  Our "position" is
 * simply the device number.
 */
static void *scull_seq_start(struct seq_file *s, loff_t *pos)
{
	if (*pos >= scull_nr_devs)
		return NULL;   /* No more to read */
	return scull_devices + *pos;
}

static void *scull_seq_next(struct seq_file *s, void *v, loff_t *pos)
{
	(*pos)++;
	if (*pos >= scull_nr_devs)
		return NULL;
	return scull_devices + *pos;
}

static void scull_seq_stop(struct seq_file *s, void *v)
{
	/* Actually, there's nothing to do here */
}

static int scull_seq_show(struct seq_file *s, void *v)
{
	struct scull_dev *dev = (struct scull_dev *) v;
	struct scull_qset *d;
	int i;

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;
	seq_printf(s, "\nDevice %i: qset %i, q %i, sz %li\n",
			(int) (dev - scull_devices), dev->qset,
			dev->quantum, dev->size);
	for (d = dev->data; d; d = d->next) { /* scan the list */
		seq_printf(s, "  item at %p, qset at %p\n", d, d->data);
		if (d->data && !d->next) /* dump only the last item */
			for (i = 0; i < dev->qset; i++) {
				if (d->data[i])
					seq_printf(s, "    % 4i: %8p\n",
							i, d->data[i]);
			}
	}
	up(&dev->sem);
	return 0;
}
	
/*
 * Tie the sequence operators up.
 */
static struct seq_operations scull_seq_ops = {
	.start = scull_seq_start,
	.next  = scull_seq_next,
	.stop  = scull_seq_stop,
	.show  = scull_seq_show
};

/*
 * Now to implement the /proc file we need only make an open
 * method which sets up the sequence operators.
 */
static int scull_proc_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &scull_seq_ops);
}

/*
 * Create a set of file operations for our proc file.
 */
static struct file_operations scull_proc_ops = {
	.owner   = THIS_MODULE,
	.open    = scull_proc_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};
	

/*
 * Actually create (and remove) the /proc file(s).
 */
//分别用新老方法实现了二个proc文件
static void scull_create_proc(void)
{
	struct proc_dir_entry *entry;
	create_proc_read_entry("scullmem", 0 /* default mode */,
			NULL /* parent dir */, scull_read_procmem,
			NULL /* client data */);
	entry = create_proc_entry("scullseq", 0, NULL);
	if (entry)
		entry->proc_fops = &scull_proc_ops;
}

static void scull_remove_proc(void)
{
	/* no problem if it was not registered */
	remove_proc_entry("scullmem", NULL /* parent dir */);
	remove_proc_entry("scullseq", NULL);
}


#endif /* SCULL_DEBUG */
//End



/* 开始实现对设备操作的方法集了,关键!!! */
/*
 * Open and close
 */
//[Tag004]
/*
open应完成的工作有：
	1.检查设备特定的错误（诸如设备未就绪或类似的硬件问题）
	2.如果设备是首次打开，则对其进行初始化；
	3.如有必要，更新f_op指针；
	4.分配并填写filp->private_data；（在这里我们只实现这项即可）
*/

/*
[形参说明]
	struct inode *inode -- 用它的i_cdev成员得到dev;
	struct file *filp -- 将得到的dev存放到他的成员private_data中；
*/
int scull_open(struct inode *inode, struct file *filp)
{
	struct scull_dev *dev; /* device information */

	dev = container_of(inode->i_cdev, struct scull_dev, cdev);
	/*
	[说明]
		1.我们要填充的应该是我们自己的特殊设备，而不是钳在他里面的字符设备结构；
		2.inode结构的i_cdev成员这能提供基本字符设备结构；
		3.这里利用了定义在<linux/kernel.h>中的宏来实现通过cdev得到dev;
	*/
	
	/*
	以后read , write ,等操作的实现中就靠他来得到dev了；
	*/
	filp->private_data = dev; /* for other methods */
	

	/* now trim to 0 the length of the device if open was write-only */
	if ( (filp->f_flags & O_ACCMODE) == O_WRONLY) {
		if (down_interruptible(&dev->sem))
			return -ERESTARTSYS;
		scull_trim(dev); /* ignore errors */
		up(&dev->sem);
	}
	return 0;          /* success */
}

/* close device file, in here we do nothing */
/* 
 * [Tag005]
 * close应完成的工作有：
 *	1.释放由open分配的，保存在filp->private_data中的所有内容；
 *  2.在最后一次关闭操作时关闭设备；
 * [注意：]并不是每次的close系统调用都会去调用到release. 在open时，也仅在open时才会创建
 * 一个新的数据结构；在fork, dup时只是增加了这个结构中维护的一个引用计数；
 * 所以当这个引用计数为0时，调用的close才意味着要释放设备数据结构，此时release才会被调用；
 */
int scull_release(struct inode *inode, struct file *filp)
{
	return 0;
}


/*
 * Follow the list
 * 
 * 第一次调用时用于创建链表；
 * 然后就是找到第n个节点；
 * 对编写驱动程序关系不大；
 */
struct scull_qset *scull_follow(struct scull_dev *dev, int n)
{
	struct scull_qset *qs = dev->data;

        /* Allocate first qset explicitly if need be */
	if (! qs) {
		qs = dev->data = kmalloc(sizeof(struct scull_qset), GFP_KERNEL);
		if (qs == NULL)
			return NULL;  /* Never mind */
		memset(qs, 0, sizeof(struct scull_qset));
	}

	/* Then follow the list */
	while (n--) {
		if (!qs->next) {
			qs->next = kmalloc(sizeof(struct scull_qset), GFP_KERNEL);
			if (qs->next == NULL)
				return NULL;  /* Never mind */
			memset(qs->next, 0, sizeof(struct scull_qset));
		}
		qs = qs->next;
		continue;
	}
	return qs;
}

/*[Tag006]
 * Data management: read and write
 * [read和write的参数]
 *		1] filp -- 文件指针；用它的成员filp->private_data得到dev;
 * 		2] buf -- 都是来自用户空间的指针；
 *  	3] count -- 缓冲区大小；(希望传输的字节数目)
 *		4] f_pos -- 指向一个长偏移量对象的指针，这个对象指明了用户在文件中进行存取
 *			操作的位置；
 *
 *[返回值]
 * 		1]如果返回值等于count，则完成了所请求数目的字节传输；
 *		2]如果返回值是正，但小于count,则继续读或写余下的数据；
 *		3]如果为0，则证明已经到了文件尾；
 *		4]如果为负，则发生了错误。会返回一个错误码，该值指明了发生了什么错误。
 * 			错误码在<linux/errno.h>中定义；
 *			例如：-EINTR (系统调用被中断)
 *				  -EFAULT (无效地址)
 */


ssize_t scull_read(struct file *filp, char __user *buf, size_t count,
                loff_t *f_pos)
{
	struct scull_dev *dev = filp->private_data; 
	struct scull_qset *dptr;	/* the first listitem */
	int quantum = dev->quantum, qset = dev->qset;
	int itemsize = quantum * qset; /* how many bytes in the listitem */
	int item, s_pos, q_pos, rest;
	ssize_t retval = 0;

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;
	if (*f_pos >= dev->size) //操作位置到文件尾，或超出文件尾了
		goto out;
	if (*f_pos + count > dev->size) //在当前位置所要读的数目超过文件尾了
		count = dev->size - *f_pos;	//减小这次的期望读取数目

	/* find listitem, qset index, and offset in the quantum */
	item = (long)*f_pos / itemsize; //确定是哪个链表项下，即哪个节点下；
	rest = (long)*f_pos % itemsize; //在这个链表项的什么位置（偏移量），用于下面找qset索引和偏移量；
	s_pos = rest / quantum;		//在这个节点里**data这个指针数组的第几行；
	 q_pos = rest % quantum; //在这行，即这个量子里的偏移量；

	/* follow the list up to the right position (defined elsewhere) */
	dptr = scull_follow(dev, item);  //找到这个链表项

	if (dptr == NULL || !dptr->data || ! dptr->data[s_pos])
		goto out; /* don't fill holes */

//以一个量子为单位传，简化了代码；
	/* read only up to the end of this quantum */
	if (count > quantum - q_pos)
		count = quantum - q_pos;

/*
 * 上面为这步准备了具体在哪个链表项的指针数组的第几行的第几列（即dptr->data[s_pos] + q_pos）
 * 从这个位置的内核态的buf中拷给用户态	
*/	

//关键一步，将数据拷给用户空间
	if (copy_to_user(buf, dptr->data[s_pos] + q_pos, count)) {
		retval = -EFAULT;
		goto out;
	}
	*f_pos += count; //更新文件指针
	retval = count;

  out:
	up(&dev->sem);
	return retval;
}

//与read的实现类似
ssize_t scull_write(struct file *filp, const char __user *buf, size_t count,
                loff_t *f_pos)
{
	struct scull_dev *dev = filp->private_data;
	struct scull_qset *dptr;
	int quantum = dev->quantum, qset = dev->qset;
	int itemsize = quantum * qset;
	int item, s_pos, q_pos, rest;
	ssize_t retval = -ENOMEM; /* value used in "goto out" statements */

	if (down_interruptible(&dev->sem))
		return -ERESTARTSYS;

	/* find listitem, qset index and offset in the quantum */
	item = (long)*f_pos / itemsize;
	rest = (long)*f_pos % itemsize;
	s_pos = rest / quantum; q_pos = rest % quantum;

	/* follow the list up to the right position */
	dptr = scull_follow(dev, item);
	if (dptr == NULL)
		goto out;
	if (!dptr->data) {
		dptr->data = kmalloc(qset * sizeof(char *), GFP_KERNEL);
		if (!dptr->data)
			goto out;
		memset(dptr->data, 0, qset * sizeof(char *));
	}
	if (!dptr->data[s_pos]) {
		dptr->data[s_pos] = kmalloc(quantum, GFP_KERNEL);
		if (!dptr->data[s_pos])
			goto out;
	}
	/* write only up to the end of this quantum */
	if (count > quantum - q_pos)
		count = quantum - q_pos;

	if (copy_from_user(dptr->data[s_pos]+q_pos, buf, count)) {
		retval = -EFAULT;
		goto out;
	}
	*f_pos += count;
	retval = count;

        /* update the size */
	if (dev->size < *f_pos)
		dev->size = *f_pos;

  out:
	up(&dev->sem);
	return retval;
}

/*
 * The ioctl() implementation
 */

int scull_ioctl(struct inode *inode, struct file *filp,
                 unsigned int cmd, unsigned long arg)
{

	int err = 0, tmp;
	int retval = 0;
    
	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if (_IOC_TYPE(cmd) != SCULL_IOC_MAGIC) return -ENOTTY;
	if (_IOC_NR(cmd) > SCULL_IOC_MAXNR) return -ENOTTY;

	/*
	 * the direction is a bitmask, and VERIFY_WRITE catches R/W
	 * transfers. `Type' is user-oriented, while
	 * access_ok is kernel-oriented, so the concept of "read" and
	 * "write" is reversed
	 */
	if (_IOC_DIR(cmd) & _IOC_READ)
		err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		err =  !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
	if (err) return -EFAULT;

	switch(cmd) {

	  case SCULL_IOCRESET:
		scull_quantum = SCULL_QUANTUM;
		scull_qset = SCULL_QSET;
		break;
        
	  case SCULL_IOCSQUANTUM: /* Set: arg points to the value */
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		retval = __get_user(scull_quantum, (int __user *)arg);
		break;

	  case SCULL_IOCTQUANTUM: /* Tell: arg is the value */
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		scull_quantum = arg;
		break;

	  case SCULL_IOCGQUANTUM: /* Get: arg is pointer to result */
		retval = __put_user(scull_quantum, (int __user *)arg);
		break;

	  case SCULL_IOCQQUANTUM: /* Query: return it (it's positive) */
		return scull_quantum;

	  case SCULL_IOCXQUANTUM: /* eXchange: use arg as pointer */
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		tmp = scull_quantum;
		retval = __get_user(scull_quantum, (int __user *)arg);
		if (retval == 0)
			retval = __put_user(tmp, (int __user *)arg);
		break;

	  case SCULL_IOCHQUANTUM: /* sHift: like Tell + Query */
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		tmp = scull_quantum;
		scull_quantum = arg;
		return tmp;
        
	  case SCULL_IOCSQSET:
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		retval = __get_user(scull_qset, (int __user *)arg);
		break;

	  case SCULL_IOCTQSET:
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		scull_qset = arg;
		break;

	  case SCULL_IOCGQSET:
		retval = __put_user(scull_qset, (int __user *)arg);
		break;

	  case SCULL_IOCQQSET:
		return scull_qset;

	  case SCULL_IOCXQSET:
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		tmp = scull_qset;
		retval = __get_user(scull_qset, (int __user *)arg);
		if (retval == 0)
			retval = put_user(tmp, (int __user *)arg);
		break;

	  case SCULL_IOCHQSET:
		if (! capable (CAP_SYS_ADMIN))
			return -EPERM;
		tmp = scull_qset;
		scull_qset = arg;
		return tmp;

        /*
         * The following two change the buffer size for scullpipe.
         * The scullpipe device uses this same ioctl method, just to
         * write less code. Actually, it's the same driver, isn't it?
         */

	  case SCULL_P_IOCTSIZE:
		scull_p_buffer = arg;
		break;

	  case SCULL_P_IOCQSIZE:
		return scull_p_buffer;


	  default:  /* redundant, as cmd was checked against MAXNR */
		return -ENOTTY;
	}
	return retval;

}



/*
 * The "extended" operations -- only seek
 */

loff_t scull_llseek(struct file *filp, loff_t off, int whence)
{
	struct scull_dev *dev = filp->private_data;
	loff_t newpos;

	switch(whence) {
	  case 0: /* SEEK_SET */
		newpos = off;
		break;

	  case 1: /* SEEK_CUR */
		newpos = filp->f_pos + off;
		break;

	  case 2: /* SEEK_END */
		newpos = dev->size + off;
		break;

	  default: /* can't happen */
		return -EINVAL;
	}
	if (newpos < 0) return -EINVAL;
	filp->f_pos = newpos;
	return newpos;
}


//[Tag007]将这组操作打包为一个对象；
struct file_operations scull_fops = {
	.owner =    THIS_MODULE,
	.llseek =   scull_llseek,
	.read =     scull_read,
	.write =    scull_write,
	.ioctl =    scull_ioctl,
	.open =     scull_open,
	.release =  scull_release,
};

/*
 * Finally, the module stuff
 */


//[Tag008]模块卸载或goto fail时；
/*
 * The cleanup function is used to handle initialization failures as well.
 * Thefore, it must be careful to work correctly even if some of the items
 * have not been initialized
 */
void scull_cleanup_module(void)
{
	int i;
	dev_t devno = MKDEV(scull_major, scull_minor);

	/* Get rid of our char dev entries */
	if (scull_devices) {
		for (i = 0; i < scull_nr_devs; i++) {
			scull_trim(scull_devices + i);
			cdev_del(&scull_devices[i].cdev);	//[???]是一个内核函数么？
		}
		kfree(scull_devices);
	}

#ifdef SCULL_DEBUG /* use proc only if debugging */
	scull_remove_proc();
#endif

	/* cleanup_module is never called if registering failed */
	unregister_chrdev_region(devno, scull_nr_devs);

	/* and call the cleanup functions for friend devices */
	scull_p_cleanup();
	scull_access_cleanup();

}


/* [Tag002] 
	这里主要干了2件事;
	在内核内部使用struct cdev结构来表示字符设备;
	[1]在这里因为我们将cdev结构嵌入到自己的scull_dev设备下了,所以我们用下面这个方法来
	初始化已分配的结构;
	cdev_init(&dev->cdev, &scull_fops);
	
	[2]告诉内核我们新结构的信息;
*/
/*
 * Set up the char_dev structure for this device.
 */
static void scull_setup_cdev(struct scull_dev *dev, int index)
{
	int err, devno = MKDEV(scull_major, scull_minor + index);
    
   // [1]
	cdev_init(&dev->cdev, &scull_fops);	/* 初始化, 字符设备和给它一组在它上面操作的方法集 */
	
	/* 填充基本字符设备的成员 */
	dev->cdev.owner = THIS_MODULE;		//模块计数
	dev->cdev.ops = &scull_fops;		//附上一组操作自己的方法集
	
//	[2]
	err = cdev_add (&dev->cdev, devno, 1);
	/*
	函数说明:
		cdev -- 字符设备的结构指针,我们就是要把他告诉给内核;
		devno -- 设备编号,用MKDEV利用全局的主设备号和次设备号生成的;
		1	-- 是应该和该设备关联的设备编号的数量, 一般情况下都为1;
			一般我们都是一个设备编号对应一个设备;		
	*/
	/*
	注意:
		在调用cdev_add后,我们的设备就被添加到系统了,他"活"了. 附加的操作集也就可以被内核调用了
		,因此,在驱动程序还没有完全准备好处理设备上的操作时,就不能调用cdev_add!
	*/
	/* Fail gracefully if need be */
	if (err)
		printk(KERN_NOTICE "Error %d adding scull%d", err, index);
}

/*[Tag000]
 * 当模块加载时，调用；但是为什么要放在最后来实现他呢，看到Tag002时，你应该就明白了；
*/
int scull_init_module(void)
{
	int result, i;
	dev_t dev = 0;

/* [Tag001] */
/* [1]分配设备编号 */
/*
 * Get a range of minor numbers to work with, asking for a dynamic
 * major unless directed otherwise at load time.
 */
	if (scull_major) { 	/* 预先自己指定了主设备号 */
		dev = MKDEV(scull_major, scull_minor); /* 利用主设备号,找到设备编号给方法1用 */
		result = register_chrdev_region(dev, scull_nr_devs, "scull");
	} else {		/* 动态自己生成设备编号,然后再利用设备编号得到主设备号;
						记住如果用这个方法那么就要后建设备文件了,因为不能提前知道主号
						当然也可以利用ldd3书中提供的脚本,巨方便&&通用 */
		result = alloc_chrdev_region(&dev, scull_minor, scull_nr_devs,
				"scull");
		scull_major = MAJOR(dev);
	}
	if (result < 0) {
		printk(KERN_WARNING "scull: can't get major %d\n", scull_major);
		return result;
	}

    /*[2]设备对象实例化*/ 
        /* 
	 * allocate the devices -- we can't have them static, as the number
	 * can be specified at load time
	 */
	scull_devices = kmalloc(scull_nr_devs * sizeof(struct scull_dev), GFP_KERNEL);
	if (!scull_devices) {
		result = -ENOMEM;
		goto fail;  /* Make this more graceful */
	}
	memset(scull_devices, 0, scull_nr_devs * sizeof(struct scull_dev));

/* [3]在这里初始化设备用了2.6的新方法,在scull_setup_cdev里完成 */
        /* Initialize each device. */
	for (i = 0; i < scull_nr_devs; i++) {
		scull_devices[i].quantum = scull_quantum;	/* 可以根据自己insmod时传参
														来自己改变量子和量子集(指针数组)的大小 */
		scull_devices[i].qset = scull_qset;
		init_MUTEX(&scull_devices[i].sem);
		scull_setup_cdev(&scull_devices[i], i);	/* 在分别完主设备编号后goto Tag002 设备注册 */
	}

        /* At this point call the init function for any friend device */
	dev = MKDEV(scull_major, scull_minor + scull_nr_devs);
	dev += scull_p_init(dev);
	dev += scull_access_init(dev);

#ifdef SCULL_DEBUG /* only when debugging */
	scull_create_proc();
#endif

	return 0; /* succeed */

  fail:
	scull_cleanup_module();
	return result;
}

module_init(scull_init_module);		//insmod	
module_exit(scull_cleanup_module);	//rmmod
