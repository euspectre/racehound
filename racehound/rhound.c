#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/err.h>
#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/mutex.h>
#include <linux/moduleparam.h>

#include <kedr/asm/insn.h>

//<>
#include <linux/smp.h>
#include <linux/sched.h>
#include <linux/kdebug.h>
#include <linux/notifier.h>
#include <asm/debugreg.h>
#include <linux/timer.h>
#include <linux/kallsyms.h>
//<>

#include "sections.h"
#include "functions.h"
#include "bp.h"

MODULE_LICENSE("GPL");

static char* target_name = "hello";
module_param(target_name, charp, S_IRUGO);

static char* target_function = "hello_plus";
module_param(target_function, charp, S_IRUGO);

static struct module* target_module = NULL;

struct dentry *debugfs_dir_dentry = NULL;
const char *debugfs_dir_name = "rhound";

struct workqueue_struct *wq;

int racefinder_changed = 0;

extern struct list_head tmod_funcs;

#define CHUNK_SIZE 4096

struct func_with_offsets {
    char *func_name;
    void *addr;
    int offsets[CHUNK_SIZE];
    int offsets_len;
    
    struct list_head lst;
};

struct list_head funcs_with_offsets;
/* ====================================================================== */

/* Offset of the insn in 'hello_plus' to set the sw bp to. */
static unsigned int bp_offset = 0x11;
module_param(bp_offset, int, S_IRUGO);

/* Set it to a non-zero value to allow resetting the timer that will place 
 * the sw bp again.
 * Set it to 0 before deleting the timer to prevent it from resetting 
 * itself. */
static int bp_reset_allowed = 0;

#define BP_TIMER_INTERVAL (HZ / 2) /* 0.5 sec expressed in jiffies */

/* Fires each BP_TIMER_INTERVAL jiffies (or more), resets the sw bp if 
 * needed. */
// TODO: prove the timer cannot be armed when this module is about to 
// unload.
static struct timer_list bp_timer;

static u8 soft_bp = 0xcc;

static int bp_set = 0; /* non-zero - sw bp is currently set, 0 - not set */

/* Address of the sw breakpoint, NULL if the target is not loaded. */
static u8 *bp_addr = NULL; 

/* The first byte of the instruction replaced with a breakpoint. Initialized
 * to 0xcc just in case. */
static u8 bp_orig_byte = 0xcc;

// TODO: get it some other way rather than lookup by name...
// All this is not needed if CONFIG_DEBUG_SET_MODULE_RONX=n. Otherwise, only
// text_poke() can help.
static struct mutex *ptext_mutex = NULL;
static void * (*do_text_poke)(void *addr, const void *opcode, size_t len) = 
    NULL;
/* ====================================================================== */

static unsigned int
get_operand_size_from_insn_attr(struct insn *insn, unsigned char opnd_type)
{
    BUG_ON(insn->length == 0);
    BUG_ON(insn->opnd_bytes == 0);
    
    switch (opnd_type)
    {
    case INAT_OPTYPE_B:
        /* Byte, regardless of operand-size attribute. */
        return 1;
    case INAT_OPTYPE_D:
        /* Doubleword, regardless of operand-size attribute. */
        return 4;
    case INAT_OPTYPE_Q:
        /* Quadword, regardless of operand-size attribute. */
        return 8;
    case INAT_OPTYPE_V:
        /* Word, doubleword or quadword (in 64-bit mode), depending 
         * on operand-size attribute. */
        return insn->opnd_bytes;
    case INAT_OPTYPE_W:
        /* Word, regardless of operand-size attribute. */
        return 2;
    case INAT_OPTYPE_Z:
        /* Word for 16-bit operand-size or doubleword for 32 or 
         * 64-bit operand-size. */
        return (insn->opnd_bytes == 2 ? 2 : 4);
    default: break;
    }
    return insn->opnd_bytes; /* just in case */
}

long get_reg_val_by_code(int code, struct pt_regs *regs)
{
    switch (code)
    {
        case (INAT_REG_CODE_AX):
            return regs->ax;
        case (INAT_REG_CODE_CX):
            return regs->cx;
        case (INAT_REG_CODE_DX):
            return regs->dx;
        case (INAT_REG_CODE_BX):
            return regs->bx;
        case (INAT_REG_CODE_SP):
            return regs->sp;
        case (INAT_REG_CODE_BP):
            return regs->bp;
        case (INAT_REG_CODE_SI):
            return regs->si;
        case (INAT_REG_CODE_DI):
            return regs->di;
#ifndef __i386__
        case (INAT_REG_CODE_8):
            return regs->r8;
        case (INAT_REG_CODE_9):
            return regs->r9;
        case (INAT_REG_CODE_10):
            return regs->r10;
        case (INAT_REG_CODE_11):
            return regs->r11;
        case (INAT_REG_CODE_12):
            return regs->r12;
        case (INAT_REG_CODE_13):
            return regs->r13;
        case (INAT_REG_CODE_14):
            return regs->r14;
        case (INAT_REG_CODE_15):
            return regs->r15;
#endif // __i386__
    }
    return 0;
}

long long get_value_with_size(void *addr, int size)
{
    /*int db_regs[5];
        asm volatile ("mov %%dr0, %0" : "=r"(db_regs[0])); 
        asm volatile ("mov %%dr1, %0" : "=r"(db_regs[1])); 
        asm volatile ("mov %%dr2, %0" : "=r"(db_regs[2])); 
        asm volatile ("mov %%dr3, %0" : "=r"(db_regs[3])); 
        asm volatile ("mov %%dr7, %0" : "=r"(db_regs[4])); 
        printk("inside get_value_with_size dr0: %x dr1: %x dr2: %x dr3: %x dr7: %x\n", db_regs[0], db_regs[1], db_regs[2], db_regs[3], db_regs[4]);*/

    if (size == 1)
    {
        return *( (uint8_t*) addr );
    }
    if (size == 2)
    {
        return *( (uint16_t*) addr );
    }
    if (size == 4)
    {
        //pr_info("[Got ya 4!]\n");
        return *( (uint32_t*) addr );
    }
    if (size == 8)
    {
    //pr_info("[Got ya 8!]\n");
    return *( (uint64_t*) addr );
    }
    if (size == 16)
    {
        return *( (uint64_t*) addr );
    }
    return *( (int*) addr );
}

long decode_and_get_addr(void *insn_addr, struct pt_regs *regs)
{
    unsigned long ea = 0; // *
    long displacement, immediate;
    long long val, newval;
//  volatile long counter;
    struct insn insn;
    int mod, reg, rm, ss, index, base, rex_r, rex_x, rex_b, size;
    /*int db_regs[5];*/

//    printk("decode_and_get_mem_addr\n");
    kernel_insn_init(&insn, insn_addr);
    insn_get_length(&insn);
    
//    printk("insn %x %d\n", (unsigned int) insn.kaddr, (unsigned int) insn.length); // *
        
    if (insn_is_mem_read(&insn) || insn_is_mem_write(&insn))
    {
//        printk("insn_is_mem_read / insn_is_mem_write\n");
        insn_get_length(&insn);  // 64bit?
        
        base = X86_SIB_BASE(insn.sib.value);
        index = X86_SIB_INDEX(insn.sib.value);
        ss = X86_SIB_SCALE(insn.sib.value);
        mod = X86_MODRM_MOD(insn.modrm.value);
        reg = X86_MODRM_REG(insn.modrm.value);
        rm = X86_MODRM_RM(insn.modrm.value);
        displacement = insn.displacement.value;
        immediate = insn.immediate.value;
        
        rex_r = X86_REX_R(insn.rex_prefix.value);
        rex_x = X86_REX_X(insn.rex_prefix.value);
        rex_b = X86_REX_B(insn.rex_prefix.value);
        
/*        printk("rex_r: %d rex_x: %d rex_b: %d\n", X86_REX_R(insn.rex_prefix.value),
                                                  X86_REX_X(insn.rex_prefix.value),
                                                  X86_REX_B(insn.rex_prefix.value));
*/        
/*        printk("base: %d index: %d scale: %d "
               "mod: %d reg: %d rm: %d " 
               "displacement: %x ebp: %lu eax: %lu "
               "immediate: %x \n", 
               X86_SIB_BASE(insn.sib.value),
               X86_SIB_INDEX(insn.sib.value),
               X86_SIB_SCALE(insn.sib.value),
               X86_MODRM_MOD(insn.modrm.value),
               X86_MODRM_REG(insn.modrm.value),
               X86_MODRM_RM(insn.modrm.value),
               insn.displacement.value,
               regs->bp,
               regs->ax,
               insn.immediate.value);
*/        
        if (immediate != 0)
        {
//            printk("immediate\n");
            ea = immediate;
        }
        else if (rm == 4)
        {
//            printk("sib\n");
            reg = reg | (rex_r<<4);
            rm = rm | (rex_b<<4);
            ea = get_reg_val_by_code(base, regs)
              + (get_reg_val_by_code(index, regs) << ss)
              +  displacement;
        }
        else
        {
//            printk("no sib\n");
            reg = reg | (rex_r<<4);
            base = base | (rex_b<<4);
            index = index | (rex_x<<4);
            ea = get_reg_val_by_code(rm, regs) + displacement;
        }
//        printk("ea: %lu\n", ea);
        size = get_operand_size_from_insn_attr(&insn, insn.attr.opnd_type1);
//        printk("size: %d\n", size);
        val = 1 /*get_value_with_size(ea, size)*/;
//        printk("*ea: %lld \n", val);
        
        racefinder_changed = 0;
        
        racefinder_set_hwbp((void *)ea);
        
        mdelay(200);
        
        racefinder_unset_hwbp();

        //printk("a1\n");
        newval = 1 /*get_value_with_size(ea, size)*/ ;
        //printk("a2\n");
        if (racefinder_changed || (val != newval) )
        {
            printk(KERN_INFO 
            "[DBG] Race detected between accesses to *%p! "
            "old_val = %lx, new_val = %lx, orig_ip: %pS, "
            "size = %d, CPU = %d, task_struct = %p\n", 
            (void *)ea, (unsigned long)val, (unsigned long)newval, 
            (void *)regs->ip, size,
            smp_processor_id(), current);
        }
        
         racefinder_changed = 0;
    }
    return ea;
}

int insn_has_fs_gs_prefixes(struct insn *insn)
{
    int i;
    insn_byte_t *prefixes = insn->prefixes.bytes;
    insn_get_prefixes(insn);
    for (i = 0; i < X86_NUM_LEGACY_PREFIXES; i++)
    {
        if (prefixes[i] == 0x64 || prefixes[i] == 0x65)
        {
            return 1;
        }
    }
    return 0;
}

int kedr_for_each_insn(unsigned long start_addr, unsigned long end_addr,
    int (*proc)(struct insn *, void *), void *data) 
{
    struct insn insn;
    int ret;
//    struct func_with_offsets *func = (struct func_with_offsets *) data;
    
    while (start_addr < end_addr) {
        kernel_insn_init(&insn, (void *)start_addr);
        insn_get_length(&insn);  /* Decode the instruction */
        if (insn.length == 0) {
            pr_err("Failed to decode instruction at %p\n",
                (const void *)start_addr);
            return -EILSEQ;
        }
        
        ret = proc(&insn, data); /* Process the instruction */
        if (ret != 0)
            return ret;
        
        start_addr += insn.length;
    }
    return 0;
}

int process_insn(struct insn* insn, void* params)
{
    int i;
    short nulls = 1;
    struct func_with_offsets *func = (struct func_with_offsets *) params;
    for (i = 0; i < insn->length; i++)
    {
        if (*(i + (unsigned char *) insn->kaddr) != 0)
        {
            nulls = 0;
        }
    }

    if (nulls != 1)
    {
        //printk("insn %x %d\n", (unsigned int) insn->kaddr, (unsigned int) insn->length); // *
        
        if ((insn_is_mem_read(insn) || insn_is_mem_write(insn)) && !insn_has_fs_gs_prefixes(insn))
        {
            //printk("insn_is_mem_read / insn_is_mem_write\n");
            if (func->offsets_len < CHUNK_SIZE)
            {
                func->offsets[func->offsets_len] = (unsigned long) insn->kaddr - (unsigned long) func->addr;
                func->offsets_len++;
            }
            else
            {
                return 1;
            }
        }
        return 0;
    }
    else
    {
        return -1;
    }
}

/* [NB] Cannot be called from atomic context */
void
racefinder_unset_breakpoint(void)
{
    mutex_lock(ptext_mutex);
    if (bp_addr != NULL && bp_set) {
        do_text_poke(bp_addr, &bp_orig_byte, 1);
        //*bp_addr = bp_orig_byte;
        bp_set = 0;
    }
    mutex_unlock(ptext_mutex);
}

static void 
work_fn_set_soft_bp(struct work_struct *work)
{
    mutex_lock(ptext_mutex);
    if (bp_addr != NULL && !bp_set) {
        bp_orig_byte = *bp_addr;
        do_text_poke(bp_addr, &soft_bp, 1);
        //*bp_addr = 0xcc;
        bp_set = 1;
    }
    mutex_unlock(ptext_mutex);
    kfree(work);
}

/*static void 
work_fn_clear_soft_bp(struct work_struct *work)
{
    racefinder_unset_breakpoint();
    kfree(work);
}*/

static void 
bp_timer_fn(unsigned long arg)
{
    int to_reset = 0;
    struct work_struct *work = NULL;
    
    to_reset = bp_reset_allowed;
    smp_rmb();
    
    if (!to_reset)
        return;
    
    /* [NB] If you call text_poke() / do_text_poke() directly and do 
     * not care about text_mutex, you do not need to use the workqueue
     * here.
     * Same if CONFIG_DEBUG_SET_MODULE_RONX=n and you are writing the 
     * opcodes directly rather than with text_poke. */
    
    work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (work != NULL) {
        INIT_WORK(work, work_fn_set_soft_bp);
        queue_work(wq, work);
    }
    else {
        pr_info("bp_timer_fn(): out of memory");
    }
    
    mod_timer(&bp_timer, jiffies + BP_TIMER_INTERVAL);
}

static int rfinder_detector_notifier_call(struct notifier_block *nb,
    unsigned long mod_state, void *vmod)
{
    struct kedr_tmod_function *pos;
    struct func_with_offsets *func;
    int ret = 0/*, i = 0*/;
    struct module* mod = (struct module *)vmod;
    BUG_ON(mod == NULL);
    
    switch(mod_state)
    {
        case MODULE_STATE_COMING:
            if((target_name != NULL)
                && (strcmp(target_name, module_name(mod)) == 0))
            {
                target_module = mod;
                printk("hello load detected, module_core=%x, core_size=%d\n", 
                       (unsigned int) mod->module_core, mod->core_size); // *
                kedr_print_section_info(target_name);
                ret = kedr_load_function_list(mod);
                if (ret) {
                    printk("Error occured while processing functions in \"%s\". Code: %d\n",
                        module_name(mod), ret);
                    goto cleanup_func_and_fail;
                }
                
                INIT_LIST_HEAD(&funcs_with_offsets);
                
                list_for_each_entry(pos, &tmod_funcs, list) {
                    /*printk("function %s: addr: %lu end: %lu size: %lu ================== \n", 
                           pos->name, (unsigned long) pos->addr, 
                           (unsigned long) pos->addr + (unsigned long) pos->text_size,
                           (unsigned long) pos->text_size);*/
                           
                    func = kmalloc(sizeof(*func), GFP_KERNEL);
                    
                    func->func_name = kmalloc(strlen(pos->name), GFP_KERNEL);
                    strcpy(func->func_name, pos->name);
                    func->addr = pos->addr;
                    func->offsets_len = 0;
                    INIT_LIST_HEAD(&(func->lst));    
                    
                    kedr_for_each_insn((unsigned long) pos->addr, 
                                       (unsigned long) pos->addr + (unsigned long) pos->text_size, 
                                       &process_insn, func);
                    list_add_tail(&func->lst, &funcs_with_offsets);
                    /*
                    printk("strcmp = %d\n", strcmp(pos->name, "hello_device_write"));
                    if (strcmp(pos->name, "hello_device_write") == 0)
                    {
                        racefinder_set_breakpoint("hello_device_write", 0x4c);
                    }
                    */
                    //printk("strcmp = %d\n", strcmp(pos->name, "hello_plus"));
                    if (strcmp(pos->name, target_function) == 0)
                    {
                        mutex_lock(ptext_mutex);
                        bp_addr = (u8 *)func->addr + bp_offset;
                        mutex_unlock(ptext_mutex);
                        //racefinder_set_breakpoint("hello_plus", 0x8);
                    }
                    
                    
                }
                /*list_for_each_entry(func, &funcs_with_offsets, lst)
                {
                    printk("func->name: %s func->offsets_len: %d\n", func->func_name, func->offsets_len);
                    for (i = 0; i < func->offsets_len; i++)
                    {
                        //printk("func->offset[%d]: %d\n", i, func->offsets[i]);
                    }
                }*/
                
                smp_wmb();
                bp_reset_allowed = 1;
                bp_timer_fn(0); 
            }
        break;
        
        case MODULE_STATE_GOING:
            if(mod == target_module)
            {
                smp_wmb();
                bp_reset_allowed = 0;
                del_timer_sync(&bp_timer);
                
                // No need to unset the sw breakpoint, the 
                // code where it is set will no longer be 
                // able to execute.
                //racefinder_unset_breakpoint();
                
                bp_addr = NULL;
                bp_orig_byte = 0xcc;
                target_module = NULL;
                printk("hello unload detected\n");
            }
        break;
    }
    cleanup_func_and_fail: 
        kedr_cleanup_function_subsystem();
    return 0;
}

static struct notifier_block detector_nb = {
    .notifier_call = rfinder_detector_notifier_call,
    .next = NULL,
    .priority = 3, /*Some number*/
};


static int 
on_soft_bp_triggered(struct die_args *args)
{
    int ret = NOTIFY_DONE;
        
    /* [???] 
     * How should we protect the access to 'bp_addr'? A spinlock in 
     * addition to text_mutex? */
     
    /* Check if it is someone else's breakpoint first. */
    if ((unsigned long)bp_addr + 1 != args->regs->ip) {
        printk(KERN_INFO "DIE_INT3, CPU=%d, task_struct=%p\n", 
            smp_processor_id(), current);
        goto out;
    }
    
    ret = NOTIFY_STOP; /* our breakpoint, we will handle it */
    
    //<>
    printk(KERN_INFO 
        "[Begin] Our software bp at %p; CPU=%d, task_struct=%p\n", 
        bp_addr, smp_processor_id(), current);
    //<>
    
    /*work = kzalloc(sizeof(*work), GFP_ATOMIC);
    if (work != NULL) {
        INIT_WORK(work, work_fn_clear_soft_bp);
        queue_work(wq, work);
    }
    else {
        pr_info("on_soft_bp_triggered: out of memory");
    }*/
    
    //*bp_addr = bp_orig_byte;
    
    /* Another ugly thing. We should lock text_mutex but we are in 
     * atomic context... */
    do_text_poke(bp_addr, &bp_orig_byte, 1);
    args->regs->ip -= 1;
    bp_set = 0;
    
    // Run the engine...
    decode_and_get_addr((void *)args->regs->ip, args->regs);
        
    //<>
    printk(KERN_INFO 
        "[End] Our software bp at %p; CPU=%d, task_struct=%p\n", 
        bp_addr, smp_processor_id(), current);
    //<>

out:
    return ret;
}

static int
my_exception_notify(struct notifier_block *unused, unsigned long val, 
    void *data)
{
    struct die_args *args = data;
    
    if (val == DIE_INT3) {
        return on_soft_bp_triggered(args);
    }
    else if (val == DIE_DEBUG) {
        unsigned long dr0, dr6, dr7;
            
        get_debugreg(dr0, 0);
        get_debugreg(dr7, 7);
        dr6 = *(unsigned long *)ERR_PTR(args->err);
        
        printk(KERN_INFO 
            "DIE_DEBUG, CPU=%d, task_struct=%p, ip: %pS, flags: 0x%lx, "
            "dr0: 0x%lx, dr6: 0x%lx, dr7: 0x%lx, "
            "single-stepping: %s\n", 
            smp_processor_id(), current,
            (void *)args->regs->ip, args->regs->flags,
            dr0, dr6, dr7,
            (dr6 & DR_STEP ? "yes" : "no"));
    }
    else {
        printk(KERN_INFO "DIE code: %lu, CPU=%d, task_struct=%p\n", 
            val, smp_processor_id(), current);
    }
    
    return NOTIFY_DONE; /* let the next handler try */
}

static struct notifier_block die_nb = {
    .notifier_call = my_exception_notify,
    .priority = 0, /* perhaps, we don't need the maximum priority */
};

static int __init racefinder_module_init(void)
{
    int ret = 0;
    
    init_timer(&bp_timer);
    bp_timer.function = bp_timer_fn;
    bp_timer.data = 0;
    bp_timer.expires = 0; /* to be set by mod_timer() later */
    
    /* ----------------------- */
    /* AN UGLY HACK. DO NOT DO THIS UNLESS THERE IS NO OTHER CHOICE. */
    ptext_mutex = (struct mutex *)kallsyms_lookup_name("text_mutex");
    if (ptext_mutex == NULL) {
        printk(KERN_INFO "[DBG] Not found: text_mutex\n");
        return -EINVAL;
    }
    
    do_text_poke = (void *)kallsyms_lookup_name("text_poke");
    if (do_text_poke == NULL) {
        printk(KERN_INFO "[DBG] Not found: text_poke\n");
        return -EINVAL;
    }
    
    printk(KERN_INFO "[DBG] &text_mutex = %p, &text_poke = %p\n",
        ptext_mutex, do_text_poke);
    /* ----------------------- */
    
    // TODO: check result
    register_module_notifier(&detector_nb);
    printk("rfinder =========================================\n");
    printk("rfinder loaded\n");
    
    ret = register_die_notifier(&die_nb);
    if (ret != 0)
            return ret;
    
    // TODO: check result
    wq = create_singlethread_workqueue("rhound");

    debugfs_dir_dentry = debugfs_create_dir(debugfs_dir_name, NULL);
    if (IS_ERR(debugfs_dir_dentry)) {
        pr_err("debugfs is not supported\n");
        ret = -ENODEV;
        goto out;
    }

    if (debugfs_dir_dentry == NULL) {
        pr_err("failed to create a directory in debugfs\n");
        ret = -EINVAL;
        goto out;
    }
    
    ret = kedr_init_section_subsystem(debugfs_dir_dentry);
    if (ret != 0)
        goto out_rmdir;
    
    ret = kedr_init_function_subsystem();
    if (ret != 0) {
        printk("Error occured in kedr_init_function_subsystem(). Code: %d\n",
            ret);
        goto out_rmdir;
    }
    
    return 0;
    
out_rmdir:
    kedr_cleanup_section_subsystem();
    debugfs_remove(debugfs_dir_dentry);
out:
    //<>
    unregister_die_notifier(&die_nb);
    //<>
    return ret;
}

static void __exit racefinder_module_exit(void)
{
    flush_workqueue( wq );

    destroy_workqueue( wq );

    
    unregister_module_notifier(&detector_nb);

    kedr_cleanup_function_subsystem();
    kedr_cleanup_section_subsystem();
    debugfs_remove(debugfs_dir_dentry);
    
    /* Just in case */
    smp_wmb();
    bp_reset_allowed = 0;
    del_timer_sync(&bp_timer);
    
    racefinder_unset_breakpoint();
    
    //racefinder_unregister_breakpoint();
    
    //<>
    unregister_die_notifier(&die_nb);
    //<>
    printk("rfinder unloaded\n");
}

module_init(racefinder_module_init);
module_exit(racefinder_module_exit);
MODULE_LICENSE("GPL");
