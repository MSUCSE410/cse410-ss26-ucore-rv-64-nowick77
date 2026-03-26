#include "syscall.h"
#include "defs.h"
#include "loader.h"
#include "syscall_ids.h"
#include "timer.h"
#include "trap.h"
#include "vm.h"
#include "proc.h"

uint64 sys_write(int fd, uint64 va, uint len)
{
	debugf("sys_write fd = %d va = %x, len = %d", fd, va, len);
	if (fd != STDOUT)
		return -1;
	struct proc *p = curr_proc();
	char str[MAX_STR_LEN];
	int size = copyinstr(p->pagetable, str, va, MIN(len, MAX_STR_LEN));
	debugf("size = %d", size);
	for (int i = 0; i < size; ++i) {
		console_putchar(str[i]);
	}
	return size;
}

__attribute__((noreturn)) void sys_exit(int code)
{
	exit(code);
	__builtin_unreachable();
}

uint64 sys_sched_yield()
{
	yield();
	return 0;
}

// Reads cycle counter, converts to seconds and microseconds, copies result to user space with copyout
uint64 sys_gettimeofday(uint64 val_addr, int _tz)
{
	// Get the current process to get page table
	struct proc *p = curr_proc();
	// Create a local TimeVal struct on the kernel stack
	// Cant write directly to val_addr because it's a user virtual address
	TimeVal val;
	// Read the hardware cycle counter
	uint64 cycle = get_cycle();
	// Convert cycles to seconds
	val.sec = cycle / CPU_FREQ;
	// Convert remaining cycles to microseconds
	val.usec = (cycle % CPU_FREQ) * 1000000 / CPU_FREQ;
	// Copy the kernelside struct to the user space virtual address
	// copyout translates the VA through the process's page table and writes there
	copyout(p->pagetable, val_addr, (char *)&val, sizeof(val));
	return 0;
}

// TODO: add support for mmap and munmap syscall.
// hint: read through docstrings in vm.c. Watching CH4 video may also help.
// Note the return value and PTE flags (especially U,X,W,R)
/*
* LAB1: you may need to define sys_task_info here
*/
int sys_task_info(uint64 ti_addr)
{
	struct proc *p = curr_proc();
	TaskInfo ti;
	ti.status = TASK_RUNNING;
	ti.time = get_cycle() / (CPU_FREQ / 1000) - p->start_time;
	for (int i = 0; i < MAX_SYSCALL_NUM; i++) {
		ti.syscall_times[i] = p->syscall_times[i];
	}
	copyout(p->pagetable, ti_addr, (char *)&ti, sizeof(ti));
	return 0;
}

extern char trap_page[];

// Allocates physical pages and maps them into the process's virtual address space with requested perms
uint64 sys_mmap(uint64 start, uint64 len, int port, int flag, int fd)
{
	// Check if start address is aligned to a page boundary 4096 bytes
	if (!PGALIGNED(start))
		return -1;
	// If requesting 0 bytes, nothing to do, return success
	if (len == 0)
		return 0;
	// Reject requests larger than 1G
	if (len > 1024 * 1024 * 1024)
		return -1;
	// Check that no bits outside of the lowest 3 are set in port
	// ~0x7 flips bits 0-2 to 0 and everything else to 1
	// ANDing with port checks if any upper bits are set
	if ((port & ~0x7) != 0)
		return -1;
	// At least one permission (read/write/exec) must be set, otherwise meaningless
	if ((port & 0x7) == 0)
		return -1;

	// Convert user facing port bits to page table entry flags
	// port bit 0 = readable  -> R (bit 1)
	// port bit 1 = writable  -> W (bit 2)
	// port bit 2 = executable -> X (bit 3)
	// U is always set so user-mode code can access this page
	int perm = PTE_U;
	if (port & 0x1) perm |= PTE_R; // If port says readable, set read flag
	if (port & 0x2) perm |= PTE_W; // If port says writable, set write flag
	if (port & 0x4) perm |= PTE_X; // If port says executable, set exec flag

	// Get the current process so we can access its page table
	struct proc *p = curr_proc();
	// Round up start + len to the next page boundary
	// This is the end of the virtual address range we need to map
	uint64 end = PGROUNDUP(start + len);

	// First pass: verify no pages in range are already mapped
	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) != 0)
			return -1; // A page is already mapped here, error
	}

	// Second pass: allocate physical pages and create mappings one page at a time
	for (uint64 va = start; va < end; va += PGSIZE) {
		void *pa = kalloc(); // Allocate one physical page 4096 bytes
		if (pa == 0)
			return -1; // Out of physical memory
		memset(pa, 0, PGSIZE); // Zero out the page
		// Create a page table entry mapping virtual address va to physical address pa
		if (mappages(p->pagetable, va, PGSIZE, (uint64)pa, perm) != 0) {
			kfree(pa); // mappages failed, free the page we just allocated
			return -1;
		}
	}
	return 0; // Success
}

// Removes virtual to physical page mappings in a range and frees the physical memory
uint64 sys_munmap(uint64 start, uint64 len)
{
	// Check if start address is aligned to a page boundary
	if (!PGALIGNED(start))
		return -1;
	// If len is 0, nothing to unmap, return success
	if (len == 0)
		return 0;

	// Get the current process to access its page table
	struct proc *p = curr_proc();
	// Round up to cover all pages that overlap with start, start+len
	uint64 end = PGROUNDUP(start + len);

	// Verify all pages in the range are currently mapped
	// If any page is unmapped, it's an error
	for (uint64 va = start; va < end; va += PGSIZE) {
		if (walkaddr(p->pagetable, va) == 0)
			return -1; // Found an unmapped page in the range, error
	}

	// Calculate how many pages to unmap
	uint64 npages = (end - start) / PGSIZE;
	// Remove the page table entries and free the underlying physical pages
	uvmunmap(p->pagetable, start, npages, 1);
	return 0; // Success
}

void syscall()
{
	struct trapframe *trapframe = curr_proc()->trapframe;
	int id = trapframe->a7, ret;
	uint64 args[6] = { trapframe->a0, trapframe->a1, trapframe->a2,
			   trapframe->a3, trapframe->a4, trapframe->a5 };
	tracef("syscall %d args = [%x, %x, %x, %x, %x, %x]", id, args[0],
	       args[1], args[2], args[3], args[4], args[5]);
	/*
	* LAB1: you may need to update syscall counter for task info here
	*/
	if (id >= 0 && id < MAX_SYSCALL_NUM) {
		curr_proc()->syscall_times[id]++;
	}
	switch (id) {
	case SYS_write:
		ret = sys_write(args[0], args[1], args[2]);
		break;
	case SYS_exit:
		sys_exit(args[0]);
		// __builtin_unreachable();
	case SYS_sched_yield:
		ret = sys_sched_yield();
		break;
	case SYS_gettimeofday:
		ret = sys_gettimeofday(args[0], args[1]);
		break;
	case SYS_task_info:
		ret = sys_task_info(args[0]);
		break;
	case SYS_mmap:
		// Call sys_mmap with: start addr, length, permissions
		ret = sys_mmap(args[0], args[1], args[2], args[3], args[4]);
		break;
	case SYS_munmap:
		// Call sys_munmap with: start addr, length
		ret = sys_munmap(args[0], args[1]);
		break;
	default:
		ret = -1;
		errorf("unknown syscall %d", id);
	}
	trapframe->a0 = ret;
	tracef("syscall ret %d", ret);
}
