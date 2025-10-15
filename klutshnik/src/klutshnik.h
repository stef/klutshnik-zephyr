#ifndef KLUTSHNIK_H
#define KLUTSHNIK_H

#include <stdint.h>
#include <sodium.h>
#include "XK.h"

typedef enum {
  DISCONNECTED,
  CONNECTED,
  //SECURE
} KlutshnikState;

typedef struct {
  uint8_t noise_sk[32];
  uint8_t ltsig_sk[crypto_sign_SECRETKEYBYTES];
  uint8_t rec_salt[32];
} CFG;

typedef struct {
  char *path;
  size_t min;
} InitFiles;

extern const InitFiles init_files[];

extern KlutshnikState kstate;

extern Noise_XK_session_t *session;
extern Noise_XK_device_t *dev;

#define inbuf_capacity (1024*32)
extern uint8_t inbuf[inbuf_capacity];
extern int inbuf_end;
extern int inbuf_start;

int send(const uint8_t *msg, const size_t msg_len);
int send_pkt(const uint8_t *msg, const size_t msg_len);
int send_plaintext(const uint8_t *msg, const size_t msg_len);
int read(size_t size, uint8_t **buf);
void printb64(const char* prefix, const size_t buf_len, const uint8_t *buf);
int load(const char* path, const size_t buf_len, uint8_t *buf);
int save(const char *path, const size_t key_len, uint8_t *key, const int open_flags);
int init_is_incomplete(void);

#endif // KLUTSHNIK_H
