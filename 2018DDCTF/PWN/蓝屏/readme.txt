提示：uuencoding

在老版本的 Windows 7 平台 (例如 2016 年的版本) 运行附件中的 poc 攻击代码，你会得到一个 n-day 漏洞蓝屏：

PAGE_FAULT_IN_NONPAGED_AREA (50)
Invalid system memory was referenced. This cannot be protected by try-except, it must be protected by a Probe. Typically the address is just plain bad or it is pointing at freed memory.
Arguments:
Arg1: f9e00000, memory referenced.
Arg2: 00000001, value 0 = read operation, 1 = write operation.
Arg3: 825a70c6, If non-zero, the instruction address which referenced the bad memory address.
Arg4: 00000000, (reserved)

请试分析这个蓝屏并提交针对 Windows 7 x86 的完整漏洞利用源代码、二进制 (以拿到 Root Shell 为目标) 及完整 Writeup 至：ddctfwriteup1@didichuxing.com。