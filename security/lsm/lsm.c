#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/fcntl.h>//for O_RDONLY
#include <linux/limits.h>//for PATH_MAX 
#include <linux/sched.h> 
#include <linux/mm.h>
#include <linux/string.h>
//#include <linux/dcache.h>
#include <linux/fs.h>
#include <asm/segment.h>
#include <linux/buffer_head.h>
#include <asm/siginfo.h>	//siginfo
#include <linux/rcupdate.h>	//rcu_read_lock
#include <linux/cdev.h>
#include <linux/debugfs.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <asm/io.h>
#include <asm/uaccess.h>
#include <linux/magic.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/nsproxy.h>
#include <linux/path.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs_struct.h>
#include <linux/proc_fs.h>

#define MAX_LENGTH 512

static char prot_rules[1024] = {0};

// Get path from task_struct
static char* get_absolute_path(struct task_struct * task, char *tpath, int len)
{
    char * ret_ptr = NULL;
    struct path base_path;

    if( task == NULL)
    {
        return -1;
    }
    memset(tpath,'\0',len);
    base_path = task->mm->exe_file->f_path;
    ret_ptr = dentry_path(base_path.dentry, tpath, len);

    return ret_ptr;
}


// Transverse all the tasks
static int find_task (char *taskName)
{
  struct task_struct *p;
  char name[512];
  char *pname;

  memset(name,0,512);
  for_each_process(p)
  {
    pname = get_absolute_path (p, name, 512);
    if (pname == -1)
	return 0;
    if ( !strcmp(pname,taskName) )
      return 1;
  }
  return 0;
}

// If filePath in protection :: Return -1
// Else			::	Return  0
static int chkPerm( char *expPath, int len )
{
  int i;
  char chkData[1024];
  
  // Check prot_rules Valid
  for(i=0;prot_rules[i]!=0 && i<1024;i++);
  if (i<1024)
    memcpy(chkData,prot_rules,1024);
  else
    memset(chkData,0,1024);

  for(i=0;chkData[i]!=0;i++)
    if( !memcmp(expPath,&chkData[i],len) )
      return -1;
  return 0;
}

static int lsm_task_kill (struct task_struct *p, struct siginfo *info, 
			 int sig, u32 secid)
// Check signal is Kill & p path is in lsm_prules file
// ptr = d_path(&task->mm->exe_file->f_path,path,PAGE_SIZE); Get Full Path
// block all the Kill sigs to the executable
// allow Only Kill sigs from kernel
{
  char exeloc[512];
  char *exepath;
  int len = 0;

  printk("LSM::Check Task Kill Permissions.\n");
  memset(exeloc,0,512);
  // Sig from Kernel
  if( info==SEND_SIG_PRIV || SI_FROMKERNEL(info) )
    return 0;
  // Filter Out Term & Kill sigs Only
  if( sig != SIGTERM && sig != SIGKILL )
    return 0;
  // Check Permission
  exepath = get_absolute_path( p, exeloc, 512);
  // Get Length
  for(;len<512 && exepath[len] != 0; len++);
  
  return chkPerm(exepath,len);
}

int isExe( char *filePath )
{
  char buf[512];
  int i;
  for(i=0;i<3;i++)
    buf[i] = '|';
  for(i=0;filePath[i]!=0;i++)
    buf[i+3] = filePath[i];
  buf[i+3] = ':';
  buf[i+4] = ':';
  buf[i+5] = ':';
  buf[i+6] = 0;

  // return 0 if not Exe
  // return -1 if is Exe
  return chkPerm(buf, i+6);
}

int isCfg( char *filePath )
{
  char buf[512];
  int i;
  for(i=0;i<3;i++)
    buf[i] = ':';
  for(i=0;filePath[i]!=0;i++)
    buf[i+3] = filePath[i];
  buf[i+3] = '\n';
  buf[i+4] = 0;

  // return 0 if not Exe
  // return -1 if is Exe
  return chkPerm(buf, i+4);
}

int relatedExeRunning( char *filePath )
{
  char chkData[1024];
  int i=0;
  int flag=0;
  int exeOff=0;
  int fileOff=0;
  int tailOff=0;

  // Check prot_rules Valid
  for(i=0;prot_rules[i]!=0 && i<1024;i++);
  if (i<1024)
    memcpy(chkData,prot_rules,1024);
  else
    memset(chkData,0,1024);

  while (i<1024 && chkData[i]!=0)
  { if (chkData[i]=='|'&&chkData[i+1]=='|'&&chkData[i+2]=='|')
      exeOff = i;
    if (chkData[i]==':'&&chkData[i+1]==':'&&chkData[i+2]==':')
      fileOff = i;
    if (chkData[i]=='\n')
      tailOff = i;
    if (tailOff>exeOff)
    { if (chkData[fileOff+3]!='\n'&&(!memcmp(filePath,&chkData[fileOff+3],tailOff-fileOff-1-3)))
        { flag=1; break; }
      else
        i = tailOff;   }
    i++;  }

  // Not Found? Error
  if (flag == 0)
    return -1;

  chkData[fileOff]=0;
  return find_task(&chkData[exeOff+3]);
}

static int lsm_file_permission (struct file *file, int mask)
// Check if (1): file->f_path.dentry->d_iname matches in lsm_prules file
//		dentry_path_raw(file->f_path.dentry,buf,len) get full path
//		d_path(&file->f_path,buf,len)
//	    (2): related program is running
//		transverse all the tasks
//		find_task return 1 ---> found
//		find_task return 0 ---> not found
{
  char buf[512];
  char *filePath;
  int flag;
  int len;

  //printk("Checking File Permissions.\n");
  memset(buf,0,512);
  filePath = dentry_path(file->f_path.dentry,buf,512);
  // Get Length
  for(len=0;len<512 && filePath[len]!=0;len++);
  if( !chkPerm(filePath, len) )
    return 0;

  // Protected
  flag = mask & FMODE_WRITE;
  if( isExe(filePath) && flag )
      return -1;
  flag = mask & FMODE_EXEC;
  if( isExe(filePath) && flag )
      return 0;
  if( isCfg(filePath) && !relatedExeRunning(filePath) )
    return 0;
  return -1;
}


static int lsm_inode_rmdir (struct inode *dir, struct dentry *dentry)
{
	char *full_name;
	char buf[MAX_LENGTH];
	int len;

	printk("LSM::Function 'inode_rmdir' has been called\n");
	memset(buf,0,MAX_LENGTH);
	full_name = dentry_path(dentry,buf,MAX_LENGTH);
	// Get Length
	for(len=0;len<MAX_LENGTH && full_name[len]!=0;len++);
	if (chkPerm(full_name, len))
	{
		printk("LSM::remove denied of the directory: %s \n",full_name);
		return 1;
	} 
	return 0;
}

static int lsm_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	char *full_name;
	char buf[MAX_LENGTH];
	int len;

	printk("LSM::Function 'inode_unlink' has been called\n");
	memset(buf,0,MAX_LENGTH);
	full_name = dentry_path(dentry,buf,MAX_LENGTH);
//	printk("fullname:%s  controlleddir:%s \n",full_name,controlleddir);
	// GET Length
	for(len=0;len<MAX_LENGTH && full_name[len]!=0;len++);
	if (chkPerm(full_name, len))
	{
		printk("LSM::remove denied of the file: %s \n",full_name);
		return 1;
	} 
	return 0;
}

static int kernel_ops(int fd, char *buf, ssize_t len)
{
	int pid=0;
	int i=1;
        char controlleddir[1024];
	struct siginfo *info;
	struct task_struct *t;
	int ret;

	printk("LSM::Writing Control Files... \n");
	if (len == 0){
		printk("LSM::Error! use K[pid] to kill the process. \n");
		return len;
	}

	memset(controlleddir,0,1024);
	if (copy_from_user(controlleddir, buf, len) != 0){
		printk("LSM::Can't get Operations! \n");
		printk("LSM::Something may be wrong, please check it! \n");
	        return len;
	}
	if (controlleddir[0]!='K' && controlleddir[0]!='R')
	{	printk("LSM::Unknown Command.\n");
		return len;	}

	if (controlleddir[0] == 'K')
	{
	  // Strictly the length of input characters
	  // eg. K123 length 4
	  while (i<len)
	    	pid = pid*10 + (buf[i]-'0');

	  // Sending Signal to Pid
	  // This is a Kernel Signal
	  info=SEND_SIG_PRIV;

	  rcu_read_lock();
	  t = pid_task(find_pid_ns(pid, &init_pid_ns), PIDTYPE_PID);	
	  if(t == NULL){
		printk("LSM::no such pid\n");
		rcu_read_unlock();
		return -ENODEV;
    	  }
	  rcu_read_unlock();
	  ret = send_sig_info(SIGKILL, info, t);    //send the signal
	  printk("LSM::Kill Proc\n");
	  if (ret < 0) {
		printk("LSM::error sending signal\n");
		return ret;
	  }
	  return 0;
	}
	
	if (controlleddir[0] == 'R')
	{
	  memcpy( prot_rules, &controlleddir[1], len-1);
	  prot_rules[1023] = 0;
	  printk("LSM::%s",prot_rules);
	  return 0;
	}
	return -1;
}

static struct file_operations fops = {
	.owner = THIS_MODULE,
	.write = kernel_ops,
};

static struct security_operations lsm_ops=
{
	.inode_rmdir = lsm_inode_rmdir,
	.inode_unlink = lsm_inode_unlink,
	.file_permission = lsm_file_permission,
	.task_kill = lsm_task_kill,
};

static int __init lsm_init(void)
{
  // Create Interative Proc file
  struct proc_dir_entry *ctlEntry;
  ctlEntry = proc_create("lsm_ctl",0,NULL,&fops);

  // Register LSM module
  if(register_security(&lsm_ops))
          {
        printk("LSM::Failure registering LSM module with kernel\n");
	return -1;
           }

  printk("LSM::LSM Module Init Success! \n");
  return 0;
}

security_initcall(lsm_init);
