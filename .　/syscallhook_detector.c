#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/unistd.h>
#include <asm/unistd.h>
#include <asm/uaccess.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");

void ** sys_call_table = (void *)0xc1360120;

char *_getname(const char *path){
	char *tmp = __getname();
	strncpy_from_user(tmp, path, PATH_MAX + 1);
	return tmp;
}

int count_keyword(const char *path, const char *key){
	int n = 0;
	char *s = (char *)path;
	int key_len = strlen(key);
	while((s=strstr(s, key)) != NULL){
		s += key_len;
		n++;
	}
	return n;
}

asmlinkage static int (*old_open)(const char __user *_path, int flags, mode_t mode);
asmlinkage static int my_open(const char __user *_path, int flags, mode_t mode){
	int n;
	char *path = _getname(_path);
	if(IS_ERR(path)) return PTR_ERR(path);
	if(strncmp(path, "/home/", 6)) return old_open(_path, flags, mode);
	n = count_keyword(path, "../");
	printk(KERN_INFO "my_open('%s', %d, %d)\n", path, flags, n);
	__putname(path);
	if(n >= 5){
		return -EPERM;
	}else{
		return old_open(_path, flags, mode);
	}
}

asmlinkage static int (*old_unlink)(const char __user *_path);                                               
asmlinkage static int my_unlink(const char __user *_path){                                                                           
        char *fixed_arg1;                                                                            
        int pid = current->pid;                                                                      
        char *comm = current->comm;               
	char *path = _getname(_path);
	if(IS_ERR(path)) return PTR_ERR(path);
	                                                           
	printk(KERN_INFO "my_unlink(%s)\n", path);
                                                                                             
        if(strcmp(path, "/bin/netstat") == 0){                                                       
                printk(KERN_INFO "[Detect Malware!!!] pid:%d name:%s behavior:unlink(%s)\n", pid, comm, path);  
        	return old_unlink(_path);
	}                                                                                            
                                                                                                     
        fixed_arg1 = strrchr(path, '/');                                                             
        if(fixed_arg1 == NULL){                                                                      
                fixed_arg1 = path;                                                                   
        }else{                                                                                       
                fixed_arg1 += 1;                                                                     
        }                                                                                            
        if(strncmp(fixed_arg1, comm, 16) == 0){                                                      
                printk(KERN_INFO "[Detect Malware!!!] pid:%d name:%s behavior:unlink(%s) self-deleting\n", pid, comm, path);
        }

	__putname(path);                                                                                           
                                                                                                     
        return old_unlink(_path);                                                                     
}

asmlinkage static int (*old_prctl)(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);                                                                           
asmlinkage static int my_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5){                                                                                 
        int pid = current->pid;                                                                                                                                                                             
        char *comm = current->comm;                                                                                                                                                                         
                                                                                                                                                                                                            
        if(option == 15){                                                                                                                                                                                   
                printk(KERN_INFO "[Detect Malware!!!] pid:%d name:%s beahvior:prctl(%d, ...) rename process\n", pid, comm, option);                                                                                    
        }                                                                                                                                                                                                   
                                                                                                                                                                                                            
        return old_prctl(option, arg2, arg3, arg4, arg5);                                                                                                                                                   
}

static int on_init(void){
	printk(KERN_INFO __FILE__ ":on_init()\n");

	old_open = sys_call_table[__NR_open];
	sys_call_table[__NR_open] = (void *)my_open;

	old_unlink = sys_call_table[__NR_unlink];
	sys_call_table[__NR_unlink] = (void *)my_unlink;

	old_prctl = sys_call_table[__NR_prctl];
	sys_call_table[__NR_prctl] = (void *)my_prctl;
	
	return 0;
}

static void on_exit(void){
	printk(KERN_INFO __FILE__ ":on_exit()\n");
	sys_call_table[__NR_open] = (void *)old_open;
	sys_call_table[__NR_unlink] = (void *)old_unlink;
	sys_call_table[__NR_prctl] = (void *)old_prctl;
}

module_init(on_init);
module_exit(on_exit);

