#ifndef _R0MOD_GLOBAL_H
#   define _R0MOD_GLOBAL_H

#   ifndef CPP
#       include <linux/module.h>
#       include <linux/printk.h>    // printk.
#   endif



// Helper functions for loggers
// INFO: ``fn`` is short for ``__func__``.
#   define fn_printk(level, fmt, ...)                               \
        printk(level "%s: " fmt, __func__, ##__VA_ARGS__)

// INFO: ``fm`` is short for ``__func__`` and ``module``.
#   define fm_printk(level, fmt, ...)                               \
        printk(level "%s.%s: " fmt,                                 \
            THIS_MODULE->name, __func__, ##__VA_ARGS__)

// INFO: I only use ``pr_alert`` at present.
#   define fn_alert(fmt, ...)                                       \
        fn_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

#   define fm_alert(fmt, ...)                                       \
        fm_printk(KERN_ALERT, fmt, ##__VA_ARGS__)

#endif
