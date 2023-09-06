#ifndef PAGE_H
#define PAGE_H

enum VM_TYPE
{
    VM_BIN,  /* memory address is executable file */
    VM_FILE, /* memory address is file */
    VM_ANON  /* anonymous memory (from swap)*/
}

struct vm_entry
{
    enum VM_TYPE type; /* store the type of VM entry */
    void *vaddr;       /* vm_entry의 가상페이지 번호 */
    bool writable;     /* True일 경우 해당 주소에 write 가능 False일 경우 해당 주소에 write 불가능 */
    bool is_loaded;    /* 물리메모리의 탑재 여부를 알려주는 플래그 */
    struct file *file; /* 가상주소와 맵핑된 파일 */

    /* Memory Mapped File 에서 다룰 예정 */
    struct list_elem mmap_elem; /* mmap 리스트 element */
    size_t offset;              /* 읽어야 할 파일 오프셋 */
    size_t read_bytes;          /* 가상페이지에 쓰여져 있는 데이터 크기 */
    size_t zero_bytes;          /* 0으로 채울 남은 페이지의 바이트 */

    /* Swapping 과제에서 다룰 예정 */
    size_t swap_slot; /* 스왑 슬롯 */
    /* ‘vm_entry들을 위한 자료구조’ 부분에서 다룰 예정 */
    struct hash_elem elem; /* 해시 테이블 Element */
};

/* initialize virtual memory using hash init */
void vm_init(struct hash *vm_hash);
/* retrieve hash using hash_int() function */
static unsigned vm_hash_func(const struct hash_elem e *, void *aux);
/* compare both hash elements a < b return true */
static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux);
/* insert into vm (use hash_insert) */
bool insert_vme(struct hash *vm, struct vm_entry *vme);
/* delete hash element entry from vm (use hash_delete) */
bool delete_vme(struct hash *vm, struct vm_entry *vme);
/* find the desired vm_entry with given virtual address (vaddr) */
struct vm_entry *find_vme(void *vaddr);
/* helper function for vm_destroy */
void hash_destroy_func(struct hash_elem *e, void *aux);
/* delete hash table entries (vm entry) and hash table buckets */
void vm_destroy(struct hash *vm);

#endif /* vm/page.h */