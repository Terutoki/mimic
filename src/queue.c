#define _GNU_SOURCE

#include <arpa/inet.h>
#include <errno.h>
#include <linux/types.h>
#include <linux/udp.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "common/checksum.h"
#include "common/defs.h"
#include "common/try.h"
#include "log.h"
#include "main.h"

int queue_push(struct queue* q, void* data, void (*data_free)(void*)) {
  struct queue_node* node = malloc(sizeof(*node));
  if (!node) return -errno;
  node->next = NULL;
  node->data = data;
  node->data_free = data_free;
  if (q->head) {
    q->tail->next = node;
    q->tail = node;
  } else {
    q->head = q->tail = node;
  }
  q->len++;
  return 0;
}

struct queue_node* queue_pop(struct queue* q) {
  if (!q || !q->head) return NULL;
  struct queue_node* result = q->head;
  q->head = q->head->next;
  result->next = NULL;
  if (!q->head) q->tail = NULL;
  q->len--;
  return result;
}

void queue_node_free(struct queue_node* node) {
  if (!node) return;
  if (node->data_free) node->data_free(node->data);
  free(node);
}

void queue_free(struct queue* q) {
  struct queue_node* node;
  while ((node = queue_pop(q))) queue_node_free(node);
  q->head = q->tail = NULL;
}

static inline struct packet* _packet_of(struct queue_node* node) {
  return (struct packet*)((char*)node + sizeof(*node));
}

static int raw_sock_idx(int family, int proto) {
  return (family == AF_INET6 ? 1 : 0) + (proto == IPPROTO_UDP ? 2 : 0);
}

int raw_sock_get(struct raw_sock_cache* cache, int family, int proto,
                 const struct in6_addr* local) {
  struct raw_sock_entry* entry = &cache->entries[raw_sock_idx(family, proto)];
  if (entry->fd >= 0 && entry->bound && memcmp(&entry->addr, local, sizeof(*local)) == 0)
    return entry->fd;

  if (entry->fd >= 0) close(entry->fd);
  entry->bound = false;

  int sk = socket(family, SOCK_RAW | SOCK_NONBLOCK, proto);
  if (sk < 0) return -errno;

  struct sockaddr_storage saddr;
  socklen_t slen;
  if (family == AF_INET) {
    struct sockaddr_in* sa = (typeof(sa))&saddr;
    *sa = (typeof(*sa)){.sin_family = AF_INET, .sin_addr = {local->s6_addr32[3]}};
    slen = sizeof(*sa);
  } else {
    struct sockaddr_in6* sa6 = (typeof(sa6))&saddr;
    *sa6 = (typeof(*sa6)){.sin6_family = AF_INET6, .sin6_addr = *local};
    slen = sizeof(*sa6);
  }

  int yes = 1;
  if (setsockopt(sk, family == AF_INET6 ? SOL_IPV6 : SOL_IP,
                 family == AF_INET6 ? IPV6_FREEBIND : IP_FREEBIND, &yes,
                 sizeof(yes)) < 0 ||
      bind(sk, (struct sockaddr*)&saddr, slen) < 0) {
    int saved = -errno;
    close(sk);
    return saved;
  }

  entry->fd = sk;
  entry->bound = true;
  entry->addr = *local;
  return sk;
}

void raw_sock_flush(struct raw_sock_cache* cache) {
  for (int i = 0; i < RAW_SOCK_ENTRIES; i++) {
    if (cache->entries[i].fd >= 0) close(cache->entries[i].fd);
    cache->entries[i] = (struct raw_sock_entry){.fd = -1};
  }
}

struct packet_buf* packet_buf_new(struct conn_tuple* conn) {
  struct packet_buf* result = calloc(1, sizeof(*result));
  if (!result) return NULL;
  result->conn = *conn;
  return result;
}

int packet_buf_push(struct packet_buf* buf, const char* data, size_t len, bool l4_csum_partial) {
  if (buf->size + len > MAX_PACKET_BUF_SIZE) return 0;  // drop new packets once buffer is full
  struct queue_node* node = malloc(sizeof(*node) + sizeof(struct packet) + len);
  if (!node) return -ENOMEM;
  node->next = NULL;
  node->data = _packet_of(node);
  node->data_free = NULL;  // payload shares the node's block
  struct packet* pkt = node->data;
  pkt->len = len;
  memcpy(pkt->data, data, len);
  if (l4_csum_partial) {
    __u32 csum = calc_csum(pkt->data, len);
    *(__be16*)(pkt->data + offsetof(struct udphdr, check)) = htons(csum_fold(csum));
  }
  if (buf->queue.head) {
    buf->queue.tail->next = node;
    buf->queue.tail = node;
  } else {
    buf->queue.head = buf->queue.tail = node;
  }
  buf->queue.len++;
  buf->size += len;
  return 0;
}

int packet_buf_consume(struct packet_buf* buf, struct raw_sock_cache* cache, bool* consumed) {
  if (!buf) {
    *consumed = true;
    return 0;
  } else if (!buf->queue.head) {
    *consumed = true;
    free(buf);
    return 0;
  }

  int sk = raw_sock_get(cache, ip_proto(&buf->conn.local), IPPROTO_UDP, &buf->conn.local);
  if (sk < 0) return sk;
  struct sockaddr_storage saddr, daddr;
  conn_tuple_to_addrs(&buf->conn, &saddr, &daddr);

  int ret = 0;
  size_t total = 0, dropped = 0;
  enum { PKT_SEND_BATCH = 64 };
  struct mmsghdr msgs[PKT_SEND_BATCH];
  struct iovec iovs[PKT_SEND_BATCH];
  struct queue_node* nodes[PKT_SEND_BATCH];
  for (;;) {
    __u32 n = 0;
    struct queue_node* pn;
    while (n < PKT_SEND_BATCH && (pn = queue_pop(&buf->queue))) {
      struct packet* p = pn->data;
      nodes[n] = pn;
      iovs[n] = (struct iovec){.iov_base = p->data, .iov_len = p->len};
      msgs[n] = (struct mmsghdr){
        .msg_hdr =
          {
            .msg_name = &daddr,
            .msg_namelen = sizeof(daddr),
            .msg_iov = &iovs[n],
            .msg_iovlen = 1,
          },
      };
      n++;
    }
    if (n == 0) break;

    // Attempt the whole batch regardless of earlier failures: a single error
    // (e.g. EAGAIN on the non-blocking socket) must not silently drop
    // the rest of the burst.
    int sent = sendmmsg(sk, msgs, n, 0);
    if (sent < 0) {
      ret = ret ?: -errno;
      dropped += n;
    } else {
      dropped += n - (__u32)sent;
    }
    total += n;
    for (__u32 i = 0; i < n; i++) queue_node_free(nodes[i]);
  }
  if (dropped) log_debug(_("packet_buf_consume: dropped %zu/%zu packet(s)"), dropped, total);

  *consumed = true;
  free(buf);
  return ret;
}

void packet_buf_drain(struct packet_buf* buf) {
  if (!buf) return;
  queue_free(&buf->queue);
  buf->size = 0;
}

void packet_buf_free(struct packet_buf* buf) {
  if (!buf) return;
  packet_buf_drain(buf);
  free(buf);
}
