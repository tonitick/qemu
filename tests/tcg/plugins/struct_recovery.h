#ifndef STRUCT_RECOVERY_H
#define STRUCT_RECOVERY_H

#include "json_parse.h"


#define STRUCT_MEM_SIZE 512
unsigned long cur_ptr_addr = 0x20000020; // pointer assignment start at 0x20000020

#define MAX_NESTED_FIELDS 100
struct NestedStruct {
    // bool is_pointer;        // whether this field is a pointer
    IsPointerType is_pointer; // whether this field is a pointer
    size_t size;            // size of this field

    union {
        unsigned int addr;  // if is_pointer, the memory address it points to
        size_t offset;      // if not is_pointer, the offset within parent struct
    } loc;

    // the follwing feildes are no needed for now
    struct NestedStruct *fields; // dynamic array of children
    size_t field_count;
    size_t field_cap;
};

/* ---------- keep track of allocated struct pointer ---------- */
#define MAX_ALLOCATED_STRUCTS 1000
struct NestedStruct* allocated_structs[MAX_ALLOCATED_STRUCTS];
size_t allocated_struct_count = 0;

int find_parent_struct_by_addr(unsigned int addr, size_t sz); // return index in allocated_structs, or -1 if not found
int find_parent_struct_by_addr(unsigned int addr, size_t sz) {
    for (size_t i = 0; i < allocated_struct_count; i++) {
        struct NestedStruct *s = allocated_structs[i];
        if (addr >= s->loc.addr && addr + sz <= s->loc.addr + STRUCT_MEM_SIZE) {
            return (int)i;
        }
    }
    return -1;
}


/* ---------- core init/new ---------- */

static inline void ns_init_ptr(struct NestedStruct *n, unsigned int addr, size_t size, bool is_confirmed) {
    // n->is_pointer  = true;
    if (is_confirmed) {
        n->is_pointer = IS_PTR_TRUE;
    } else {
        n->is_pointer = IS_PTR_UNKNOWN;
    }
    n->size        = size;
    n->loc.addr    = addr;
    n->fields      = NULL;
    n->field_count = 0;
    n->field_cap   = 0;
}

static inline void ns_init_off(struct NestedStruct *n, size_t offset, size_t size) {
    // n->is_pointer  = false;
    n->is_pointer  = IS_PTR_FALSE;
    n->size        = size;
    n->loc.offset  = offset;
    n->fields      = NULL;
    n->field_count = 0;
    n->field_cap   = 0;
}

static inline struct NestedStruct *ns_new_ptr(unsigned int addr, size_t size, bool is_confirmed) {
    struct NestedStruct *n = (struct NestedStruct *)calloc(1, sizeof *n);
    if (n) ns_init_ptr(n, addr, size, is_confirmed);
    return n;
}

static inline struct NestedStruct *ns_new_off(size_t offset, size_t size) {
    struct NestedStruct *n = (struct NestedStruct *)calloc(1, sizeof *n);
    if (n) ns_init_off(n, offset, size);
    return n;
}

// /* ---------- children management ---------- */

// static inline size_t ns_max_grow(size_t want) {
//     return want > MAX_NESTED_FIELDS ? MAX_NESTED_FIELDS : want;
// }

// static inline int ns_reserve_children(struct NestedStruct *n, size_t want) {
//     if (want <= n->field_cap) return 1;
//     want = ns_max_grow(want);
//     if (want <= n->field_cap) return 1;           // already capped

//     size_t cap = n->field_cap ? n->field_cap : 4;
//     while (cap < want) {
//         size_t next = cap * 2;
//         if (next > MAX_NESTED_FIELDS) { next = MAX_NESTED_FIELDS; }
//         if (next == cap) break;
//         cap = next;
//     }

//     if (cap > MAX_NESTED_FIELDS) cap = MAX_NESTED_FIELDS;
//     if (cap == n->field_cap) return 0;            // cannot grow further

//     void *p = realloc(n->fields, cap * sizeof *n->fields);
//     if (!p) return 0;

//     n->fields    = (struct NestedStruct *)p;
//     /* zero-initialize the newly added tail for safety */
//     if (cap > n->field_cap) {
//         size_t added = cap - n->field_cap;
//         memset(n->fields + n->field_cap, 0, added * sizeof *n->fields);
//     }
//     n->field_cap = cap;
//     return 1;
// }

// /* Append a zeroed child, return pointer to it (or NULL on failure). */
// static inline struct NestedStruct *ns_add_child_blank(struct NestedStruct *parent) {
//     if (parent->field_count >= MAX_NESTED_FIELDS && parent->field_cap < MAX_NESTED_FIELDS) {
//         if (!ns_reserve_children(parent, parent->field_count + 1)) return NULL;
//     } else if (parent->field_count >= parent->field_cap) {
//         if (!ns_reserve_children(parent, parent->field_count + 1)) return NULL;
//     }
//     if (parent->field_count >= parent->field_cap) return NULL;

//     struct NestedStruct *slot = &parent->fields[parent->field_count++];
//     memset(slot, 0, sizeof *slot);
//     return slot;
// }

// /* Append by copying a template; deep child tree is NOT copied (to avoid aliasing). */
// static inline struct NestedStruct *ns_add_child_copy(struct NestedStruct *parent,
//                                                      const struct NestedStruct *templ) {
//     struct NestedStruct *slot = ns_add_child_blank(parent);
//     if (!slot) return NULL;
//     *slot = *templ;               // shallow copy
//     slot->fields = NULL;          // break aliasing
//     slot->field_count = 0;
//     slot->field_cap = 0;
//     return slot;
// }

// /* Convenience wrappers that construct-in-place. */
// static inline struct NestedStruct *ns_add_child_ptr(struct NestedStruct *parent,
//                                                     unsigned int addr, size_t size, bool is_confirmed) {
//     struct NestedStruct *c = ns_add_child_blank(parent);
//     if (!c) return NULL;
//     ns_init_ptr(c, addr, size, is_confirmed);
//     return c;
// }

// static inline struct NestedStruct *ns_add_child_off(struct NestedStruct *parent,
//                                                     size_t offset, size_t size) {
//     struct NestedStruct *c = ns_add_child_blank(parent);
//     if (!c) return NULL;
//     ns_init_off(c, offset, size);
//     return c;
// }

// /* ---------- utilities ---------- */

// static inline void ns_print(const struct NestedStruct *n, int depth) {
//     for (int i = 0; i < depth; ++i) fputs("  ", stdout);
//     // if (n->is_pointer)
//     if (n->is_pointer == IS_PTR_TRUE || n->is_pointer == IS_PTR_UNKNOWN)
//         printf("ptr(addr=0x%08x, size=%zu)\n", n->loc.addr, n->size);
//     else
//         printf("field(offset=%zu, size=%zu)\n", n->loc.offset, n->size);

//     for (size_t i = 0; i < n->field_count; ++i)
//         ns_print(&n->fields[i], depth + 1);
// }

// /* Deep free (for stack-allocated roots, call this and NOT free(root)). */
// static inline void ns_free_recursive(struct NestedStruct *n) {
//     if (!n) return;
//     for (size_t i = 0; i < n->field_count; ++i)
//         ns_free_recursive(&n->fields[i]);
//     free(n->fields);
//     n->fields = NULL;
//     n->field_count = 0;
//     n->field_cap = 0;
// }

// /* Find first child by offset (non-pointer fields). Returns NULL if not found. */
// static inline struct NestedStruct *ns_find_child_by_offset(struct NestedStruct *parent,
//                                                            size_t offset) {
//     if (!parent) return NULL;
//     for (size_t i = 0; i < parent->field_count; ++i) {
//         struct NestedStruct *c = &parent->fields[i];
//         if (!c->is_pointer && c->loc.offset == offset) return c;
//     }
//     return NULL;
// }

// /* Find first child covering an address range [addr, addr+size). */
// static inline struct NestedStruct *ns_find_child_by_addr_cover(struct NestedStruct *parent,
//                                                                unsigned int addr, size_t size) {
//     if (!parent) return NULL;
//     unsigned int end = addr + (unsigned int)size;
//     for (size_t i = 0; i < parent->field_count; ++i) {
//         struct NestedStruct *c = &parent->fields[i];
//         if (c->is_pointer) {
//             unsigned int c_end = c->loc.addr + (unsigned int)c->size;
//             if (addr >= c->loc.addr && end <= c_end) return c;
//         }
//     }
//     return NULL;
// }



#endif // STRUCT_RECOVERY_H
