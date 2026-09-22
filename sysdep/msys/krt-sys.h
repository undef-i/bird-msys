#ifndef _BIRD_MSYS_KRT_SYS_H_
#define _BIRD_MSYS_KRT_SYS_H_

struct kif_params { };
struct kif_state { };

static inline void kif_sys_init(struct kif_proto *p UNUSED) { }
static inline void kif_sys_start(struct kif_proto *p UNUSED) { }
static inline void kif_sys_shutdown(struct kif_proto *p UNUSED) { }
static inline int kif_sys_reconfigure(struct kif_proto *p UNUSED, struct kif_config *n UNUSED, struct kif_config *o UNUSED) { return 1; }
static inline void kif_sys_preconfig(struct config *c UNUSED) { }
static inline void kif_sys_postconfig(struct kif_config *c UNUSED) { }
static inline void kif_sys_init_config(struct kif_config *c UNUSED) { }
static inline void kif_sys_copy_config(struct kif_config *d UNUSED, struct kif_config *s UNUSED) { }

struct krt_params {
  int table_id;
  u32 metric;
};

#define EA_KRT_PREFSRC EA_CODE(PROTOCOL_KERNEL, 0x10)
#define KRT_ALLOW_MERGE_PATHS 1

struct krt_state {
  node n;
};

void krt_sys_io_init(void);
void krt_sys_init(struct krt_proto *p);
static inline int krt_sys_start(struct krt_proto *p UNUSED) { return 1; }
void krt_sys_shutdown(struct krt_proto *p);
static inline int krt_sys_reconfigure(struct krt_proto *p UNUSED, struct krt_config *n UNUSED, struct krt_config *o UNUSED) { return 1; }
static inline void krt_sys_preconfig(struct config *c UNUSED) { }
static inline void krt_sys_postconfig(struct krt_config *c UNUSED) { }
static inline void krt_sys_init_config(struct krt_config *c UNUSED) { }
static inline void krt_sys_copy_config(struct krt_config *d UNUSED, struct krt_config *s UNUSED) { }
int krt_sys_get_attr(const eattr *a, byte *buf, int buflen);

#endif
