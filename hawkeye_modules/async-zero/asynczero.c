#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/mmzone.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/highmem.h>
#include <linux/kthread.h>
#include <asm/page_64.h>

static struct task_struct *asynczero_task = NULL;
static volatile bool asynczero_should_stop = false;

static int sleep = 1000;
module_param(sleep, int, 0644);
static int count = 10;
module_param(count, int, 0644);

/* clear the largest order blocks in the buddy allocator */
static int zero_fill_order = MAX_ORDER - 1;
static unsigned long pages_zeroed = 0;
module_param(pages_zeroed, ulong, 0444);

static inline bool skip_zone(struct zone *zone)
{
	return false;
}

/*
 * preferrably use the architecture specific extensions to zero-fill a page.
 * use memset as a fallback option.
 */
static inline void zero_fill_page_ntstores(struct page *page)
{
	void *kaddr;
	kaddr = kmap_atomic(page);
	__asm__ (
		"push %%rax;"
		"push %%rcx;"
		"push %%rdi;"
		"movq	%0, %%rdi;"
		"xorq    %%rax, %%rax;"
		"movl    $4096/64, %%ecx;"
		".p2align 4;"
		"1:;"
		"decl    %%ecx;"
		"movnti  %%rax,(%%rdi);"
		"movnti  %%rax,0x8(%%rdi);"
		"movnti  %%rax,0x10(%%rdi);"
		"movnti  %%rax,0x18(%%rdi);"
		"movnti  %%rax,0x20(%%rdi);"
		"movnti  %%rax,0x28(%%rdi);"
		"movnti  %%rax,0x30(%%rdi);"
		"movnti  %%rax,0x38(%%rdi);"
		"leaq    64(%%rdi),%%rdi;"
		"jnz     1b;"
		"nop;"
		"pop %%rdi;"
		"pop %%rcx;"
		"pop %%rax;"
		:: "a" (kaddr)
	);
	kunmap_atomic(kaddr);
}

/* the core logic to zero-fill a compound page */
static inline void zero_fill_compound_page(struct page *page, int order)
{
	int i;

	if (PageZeroed(page))
		return;

	for (i = 0; i < (1 << order); i++) {
		/* kernel's in-built zeroing function */
		//clear_highpage(page + i);

		/* custom zero-filling logic */
		zero_fill_page_ntstores(page + i);
	}
	//pages_zeroed += (1 << order);
	pages_zeroed++;
	SetPageZeroed(page);
}

static void zero_fill_zone_pages(struct zone *zone)
{
	struct page *page;
	struct free_area *area;
	unsigned long flags;
	unsigned long retries = 0;

	while (retries < 100 && !asynczero_should_stop) {
		/* remove one page with the lock held */
		spin_lock_irqsave(&zone->lock, flags);
		area = &(zone->free_area[zero_fill_order]);
		page = list_first_entry_or_null(&area->free_list[MIGRATE_MOVABLE],
				struct page, lru);
		if (!page) {
			//printk(KERN_ERR"no suitable page found for zeroing\n");
			spin_unlock_irqrestore(&zone->lock, flags);
			break;;
		}
		if (PageZeroed(page)) {
			retries++;
			/* move this page to the tail */
			list_del(&page->lru);
			list_add_tail(&page->lru, &area->free_list[MIGRATE_MOVABLE]);
			spin_unlock_irqrestore(&zone->lock, flags);
			continue;
		}
		list_del(&page->lru);
		area->nr_free--;
		spin_unlock_irqrestore(&zone->lock, flags);

		/* take the desired action here (zero fill in this case) */
		zero_fill_compound_page(page, zero_fill_order);

		/* add the page back to free list but at the tail */
		spin_lock_irqsave(&zone->lock, flags);
		list_add_tail(&page->lru, &area->free_list[MIGRATE_MOVABLE]);
		area->nr_free++;
		spin_unlock_irqrestore(&zone->lock, flags);
		if (pages_zeroed % count == 0)
			msleep(sleep);
	}
	/* sleep unconditionally to avoid unnnecessary looping */
	msleep(sleep);
}

static int asynczero_do_work(void *data)
{
	struct zone *zone;

	/* loop forever to check for zeroing opportunity */
	while (!asynczero_should_stop) {
		for_each_zone(zone) {
			if (!populated_zone(zone) || skip_zone(zone))
				continue;

			zero_fill_zone_pages(zone);
		}
		trace_printk("Pages zeroed: %ld\n", pages_zeroed);
	}
	return 0;
}

int init_module(void)
{
	int err;

	asynczero_should_stop = false;
	asynczero_task = kthread_run(asynczero_do_work, NULL, "kasynczerod");

	if (IS_ERR(asynczero_task)) {
		err = PTR_ERR(asynczero_task);
		asynczero_task = NULL;
		return err;
	}

	printk(KERN_INFO"asynczero: started\n");

	return 0;
}

void cleanup_module(void)
{
	if (asynczero_task) {
		asynczero_should_stop = true;
		kthread_stop(asynczero_task);
	}

	printk(KERN_INFO"asynczero: exiting\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Ashish Panwar");
