#include "page.h"
#include "../threads/thread.h"
#include "../threads/vaddr.h"
#include "../threads/palloc.h"
#include "../lib/kernel/hash.h"
#include "../userprog/pagedir.h"
#include <stdio.h>

void vm_init(struct hash *vm_hash)
{
    ASSERT(vm_hash);
    bool ret;
    ret = hash_init(vm_hash, vm_hash_func, vm_less_func, UNUSED);
    ASSERT(ret);
}
static unsigned vm_hash_func(const struct hash_elem e *, void *aux)
{
    ASSERT(e);
    return hash_int((int)e);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux)
{
    ASSERT(a);
    ASSERT(b);
    void *a_vaddr = hash_entry(a, struct vm_entry, vaddr);
    void *b_vaddr = hash_entry(b, struct vm_entry, vaddr);

    return (a_vaddr < b_vaddr) ? true : false;
}

bool insert_vme(struct hash *vm, struct vm_entry *vme)
{
    ASSERT(vm);
    ASSERT(vme);
    if (hash_insert(vm, vme->elem))
    {
        return true;
    }
    return false;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme)
{
    ASSERT(vm);
    ASSERT(vme);
    if (hash_delete(vm, vme->elem))
    {
        return true;
    }
    return false;
}

struct vm_entry *find_vme(void *vaddr)
{
    struct hash vm_hash = thread_current()->vm_hash;
    struct vm_entry vme;
    struct hash_elem *elem;

    vme.vaddr = pg_round_down(vaddr);
    elem = hash_find(vm_hash, &vme.elem);

    if (elem != NULL)
    {
        return hash_entry(elem, struct vm_entry, elem);
    }
    return NULL;
}

void vm_destroy_func(struct hash_elem *e, void *aux)
{
    struct vm_entry *hash_vm_entry = hash_entry(e, struct vm_entry, elem);
    /* if the current vm entry is loaded into memory */
    if (hash_vm_entry->is_loaded)
    {
        /* free page */
        palloc_free_page(hash_vm_entry->vaddr);
        /* remove page mapping */
        pagedir_clear_page(thread_current()->pagedir, hash_vm_entry->vaddr);
    }
    /* free vm entry structure */
    free(hash_vm_entry);
}

void vm_destroy(struct hash *vm)
{
    hash_destroy(vm, vm_destroy_func);
}
