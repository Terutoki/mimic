#ifndef MIMIC_MAIN_H
#define MIMIC_MAIN_H

#include <bpf/bpf.h>
#include <linux/types.h>
#include <net/if.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "common/defs.h"
#include "common/try.h"

struct args {
  enum {
    CMD_NULL,
    CMD_RUN,
    CMD_SHOW,
  } cmd;
  union {
    struct run_args {
      const char *ifname, *file;
      struct filter_list {
        struct filter_node {
          struct filter filter;
          struct filter_info info;
          struct filter_node* next;
        } *head, *tail;
      } filters;
      unsigned int wildcard_count;  // TODO: maybe separate v4 and v6
      struct filter_settings gsettings;
      int xdp_mode;
      enum link_type link_type;
#ifdef MIMIC_USE_LIBXDP
      bool use_libxdp;
#endif
      bool check;
    } run;
    struct show_args {
      const char* ifname;
      bool show_process, show_command;
    } show;
  };
};

struct filter_node* filter_list_add(struct filter_list* list);
void filter_list_destroy(struct filter_list* list);
void args_destroy(struct args* args);

extern const struct argp argp;
extern const struct argp run_argp;
extern const struct argp show_argp;

int subcmd_run(struct run_args* args);

int show_overview(int ifindex, enum link_type link_type, int whitelist_fd,
                  struct filter_settings* gsettings, int log_verbosity);
int subcmd_show(struct show_args* args);

struct lock_content {
  pid_t pid;
  enum link_type link_type;
  int egress_id, ingress_id;
  int whitelist_id, conns_id;
  struct filter_settings settings;
};

int parse_link_type(const char* str, enum link_type* link);
int parse_handshake(char* str, struct filter_handshake* h);
int parse_keepalive(char* str, struct filter_keepalive* k);
int parse_padding(const char* str, __s16* padding);
int parse_filter(char* filter_str, struct filter_list* list, unsigned int* wildcard_count);
int parse_xdp_mode(const char* mode);
int parse_config_file(FILE* file, struct run_args* args);
int parse_lock_file(FILE* file, struct lock_content* c, bool strict);
int write_lock_file(int fd, const struct lock_content* c);

struct queue {
  struct queue_node {
    struct queue_node* next;
    void* data;
    void (*data_free)(void*);
  } *head, *tail;
  size_t len;
};

int queue_push(struct queue* q, void* data, void (*data_free)(void*));
struct queue_node* queue_pop(struct queue* q);
void queue_node_free(struct queue_node* node);
void queue_free(struct queue* q);

// Cap buffered bytes per connection so a stalled handshake cannot OOM userspace
#define MAX_PACKET_BUF_SIZE (1 << 24)
struct packet_buf {
  struct conn_tuple conn;
  struct queue queue;
  size_t size;
};

struct packet {
  size_t len;
  char data[];
};

// packet_buf_push allocates node and packet payload in ONE block:
// [queue_node][packet header][data]; node.data_free stays NULL so
// queue_node_free frees the whole block with the node itself.

struct raw_sock_cache;

// conn-keyed handshake buffer table (userspace owns the buffers; see queue.c)
#define PKTBUF_BUCKETS 2048
#define PKTBUF_MAX_CONNS 4096
#define PKTBUF_GLOBAL_CAP (1 << 29) /* 512 MiB total buffered payload */

struct pktbuf_slot {
  struct conn_tuple key;
  struct packet_buf* buf;
  struct pktbuf_slot* next;
};

struct pktbuf_table {
  struct pktbuf_slot* buckets[PKTBUF_BUCKETS];
  size_t conns, bytes;
  pthread_mutex_t lock;
};

struct packet_buf* packet_buf_new(const struct conn_tuple* conn);
int packet_buf_push(struct packet_buf* buf, const char* data, size_t len, bool l4_csum_partial);
int packet_buf_consume(struct packet_buf* buf, struct raw_sock_cache* cache,
                       bool* consumed);
void packet_buf_drain(struct packet_buf* buf);
void packet_buf_free(struct packet_buf* buf);

int pktbuf_table_push(struct pktbuf_table* table, const struct conn_tuple* key, const char* data,
                      size_t len, bool l4_csum_partial);
int pktbuf_table_consume(struct pktbuf_table* table, const struct conn_tuple* key,
                         struct raw_sock_cache* cache);
void pktbuf_table_free(struct pktbuf_table* table, const struct conn_tuple* key);
void pktbuf_table_destroy(struct pktbuf_table* table);

enum { RAW_SOCK_ENTRIES = 32 };

struct raw_sock_entry {
  int fd;
  bool bound;
  struct in6_addr addr;
};

struct raw_sock_cache {
  struct raw_sock_entry entries[RAW_SOCK_ENTRIES];
  char mtu_ifname[IFNAMSIZ];
  unsigned int mtu;
};

int raw_sock_get(struct raw_sock_cache* cache, int family, int proto,
                 const struct in6_addr* local);
void raw_sock_flush(struct raw_sock_cache* cache);
static inline void raw_sock_cache_init(struct raw_sock_cache* cache) {
  for (int i = 0; i < RAW_SOCK_ENTRIES; i++) cache->entries[i].fd = -1;
  cache->mtu = 0;
  cache->mtu_ifname[0] = '\0';
}

int notify_ready();

void get_lock_file_name(char* dest, size_t dest_len, int ifindex);
void conn_tuple_to_addrs(const struct conn_tuple* conn, struct sockaddr_storage* saddr,
                         struct sockaddr_storage* daddr);

void ip_fmt(const struct in6_addr* ip, char* dest);
void ip_port_fmt(const struct in6_addr* ip, __be16 port, char* dest);
void filter_fmt(const struct filter* filter, char* dest);
const char* conn_state_to_str(enum conn_state s);

struct bpf_map_iter {
  int map_fd;
  const char* map_name;
  bool has_key, first_key;
};

static inline int bpf_map_iter_next(struct bpf_map_iter* iter, void* key) {
  int ret = bpf_map_get_next_key(iter->map_fd, iter->has_key ? key : NULL, key);
  if (ret == -ENOENT) {
    return 0;
  } else if (ret < 0) {
    ret(ret, _("failed to get next key of map '%s': %s"), iter->map_name, strerror(-ret));
  } else {
    iter->first_key = !iter->has_key;
    iter->has_key = true;
    return 1;
  }
}

#endif  // MIMIC_MAIN_H
