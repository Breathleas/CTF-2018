在老版本的 Windows 7/8/8.1 x64 平台 (例如 2014 年的版本) 运行附件中的 poc 代码，你会得到一个 n-day 漏洞蓝屏 [1]：

KERNEL_MODE_HEAP_CORRUPTION (13a)
The kernel mode heap manager has detected corruption in a heap.
Arguments:
Arg1: 000000000000000c, A corrupt free list was detected.
Arg2: fffff90140800000, Address of the heap that reported the corruption
Arg3: fffff9014082b620, Address at which the corruption was detected
Arg4: 0000000000000000

请试分析这个蓝屏并提交针对 Windows 8.1 x64 的完整漏洞利用源代码、二进制 (以拿到 Root Shell 为目标) 及完整 Writeup 至：ddctfwriteup2@didichuxing.com。

[1] 针对 Win32k.sys 模块开启驱动校验 Special Pool 选项将有助于观察这个问题。