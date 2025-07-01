/*
 * Copyright (c) 2020 stf
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/kernel.h>
#include <zephyr/types.h>
#include <stddef.h>
#include <zephyr/sys/util.h>
#include <zephyr/devicetree.h>
#include <stdlib.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/reboot.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/services/nus.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/storage/flash_map.h>
#include <zephyr/drivers/entropy.h>
#include <zephyr/sys/base64.h>
#include <zephyr/net/net_ip.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>

#include <sodium.h>
#include <string.h>
#include "XK.h"
#include "utils.h"
#include "toprf.h"
#include "dkg-vss.h"
#include "mpmult.h"
#include "stp-dkg.h"
#include "toprf-update.h"

LOG_MODULE_REGISTER(klutshnik, CONFIG_KLUTSHNIK_LOG_LEVEL);

#define MTU 20
#define DEVICE_NAME		CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN		(sizeof(DEVICE_NAME) - 1)
#define AEAD_KEY_SIZE 32

#define PARTITION_NODE DT_NODELABEL(lfs1)
#define MAX_PATH_LEN 255
#define MKFS_FS_TYPE FS_LITTLEFS
#define MKFS_DEV_ID FIXED_PARTITION_ID(lfs1_partition)
#define MKFS_FLAGS 0

#if DT_NODE_EXISTS(PARTITION_NODE)
FS_FSTAB_DECLARE_ENTRY(PARTITION_NODE);
#else /* PARTITION_NODE */
FS_LITTLEFS_DECLARE_DEFAULT_CONFIG(storage);
static struct fs_mount_t lfs_storage_mnt = {
   .type = FS_LITTLEFS,
   .fs_data = &storage,
   .storage_dev = (void *)FIXED_PARTITION_ID(lfs1_partition),
   .mnt_point = "/lfs",
};
#endif /* PARTITION_NODE */

   struct fs_mount_t *mountpoint =
#if DT_NODE_EXISTS(PARTITION_NODE)
      &FS_FSTAB_ENTRY(PARTITION_NODE)
#else
      &lfs_storage_mnt
#endif
      ;

// todo use cfg
static const uint8_t server_sk[] = { 0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52 };
static const uint8_t client_pk[] = { 0xc0, 0xb8, 0xc7, 0x27, 0xa9, 0xe3, 0x64, 0x8a, 0x5a, 0x02, 0xec, 0x50, 0xda, 0x62, 0xb5, 0x3a, 0x32, 0xe1, 0x62, 0x41, 0xee, 0xd0, 0x61, 0xa3, 0x9b, 0xf1, 0xc5, 0x7d, 0x28, 0xb9, 0x8b, 0x23 };

typedef struct {
  uint8_t keyid[32];
  uint8_t ltsig[32];
  uint8_t noise[32];
} AuthKeys;

typedef enum {
  DISCONNECTED,
  CONNECTED,
  //SECURE
} ConnectionState;


typedef enum {
    /// KMS ops
    OP_CREATE  = 0,
    OP_UPDATE  = 0x33,
    OP_REFRESH = 0x55,
    OP_DECRYPT = 0x66,
    OP_DELETE  = 0xff,

    /// authorization administration ops
    OP_MODAUTH = 0xaa,
} KlutshnikOp;

typedef enum {
    OWNER_perm   = 1,
    DECRYPT_perm = 2,
    UPDATE_perm  = 4,
    DELETE_perm  = 8,
} KlutshnikPerms;

typedef struct {
  uint8_t op;
  uint8_t version;
  uint8_t id[crypto_generichash_BYTES];
  uint8_t msg0[stpvssdkg_start_msg_SIZE];
} __attribute__((__packed__)) CreateReq;

typedef struct {
  uint8_t op;
  uint8_t version;
  uint8_t id[crypto_generichash_BYTES];
  uint8_t msg0[toprfupdate_stp_start_msg_SIZE];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
} __attribute__((__packed__)) UpdateReq;

typedef struct {
  uint8_t op;
  uint8_t version;
  uint8_t id[crypto_generichash_BYTES];
  uint8_t alpha[crypto_core_ristretto255_BYTES];
  uint8_t verifier[crypto_core_ristretto255_BYTES];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
} __attribute__((__packed__)) DecryptReq;

typedef struct {
  uint8_t op;
  uint8_t version;
  uint8_t id[crypto_generichash_BYTES];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
} __attribute__((__packed__)) DeleteReq;

typedef struct {
  uint8_t op;
  uint8_t version;
  uint8_t id[crypto_generichash_BYTES];
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
} __attribute__((__packed__)) RefreshReq;

typedef struct {
  uint8_t op;
  uint8_t version;
  uint8_t id[crypto_generichash_BYTES];
  uint8_t readonly;
} __attribute__((__packed__)) ModAuthReq;

static int trace = 1;
static volatile uint8_t inbuf[1024*32];
static volatile int inbuf_end=0;
static int inbuf_start=0;
static volatile ConnectionState cstate=DISCONNECTED;
static volatile struct bt_conn *c=NULL;
static Noise_XK_session_t *session=NULL;
static Noise_XK_device_t *dev=NULL;

static const struct bt_data ad[] = {
	BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
	BT_DATA(BT_DATA_NAME_COMPLETE, DEVICE_NAME, DEVICE_NAME_LEN),
};

static const struct bt_data sd[] = {
	BT_DATA_BYTES(BT_DATA_UUID128_ALL, BT_UUID_NUS_SRV_VAL),
};

static void notif_enabled(bool enabled, void *ctx) {
	ARG_UNUSED(ctx);
	LOG_INF("%s() - %s", __func__, (enabled ? "Enabled" : "Disabled"));
}

typedef struct {
  uint8_t noise_sk[32];
  uint8_t noise_pk[32];
  uint8_t ltsig_sk[crypto_sign_SECRETKEYBYTES];
  uint8_t ltsig_pk[crypto_sign_PUBLICKEYBYTES];
  uint8_t rec_salt[32];
} CFG;

// todo use config
#include "authorized_keys.c"

static uint64_t ref_time;
uint64_t ztime(void) {
  uint64_t now = k_uptime_seconds();
  //if(trace) printk("ztime: now = %lld, ztime = %lld\n", now, now + ref_time);
  return htonll(now + ref_time);
}

static void received(struct bt_conn *conn, const void *data, uint16_t len, void *ctx) {
	ARG_UNUSED(conn);
	ARG_UNUSED(ctx);

   if(cstate!=CONNECTED) {
     LOG_ERR("received %d bytes, but we are in disconnected state", len);
     return;
   }

   //if(trace) {
   //  uint8_t hex[MTU*2+1];
   //  hex[sizeof(hex)-1]=0;
   //  bin2hex(data,len,hex,sizeof(hex));
   //  printk("%s() - Len: %d, Message: %s\n", __func__, len, hex);
   //}
   if(len + inbuf_end<sizeof(inbuf)) {
      memcpy(inbuf+inbuf_end, data, len);
      inbuf_end+=len;
   }
}

struct bt_nus_cb nus_listener = {
	.notif_enabled = notif_enabled,
	.received = received,
};

static void connected(struct bt_conn *conn, uint8_t err) {
  if (err) {
    LOG_ERR("Connection failed (err 0x%02x)", err);
  } else {
    const bt_addr_le_t *addr = bt_conn_get_dst (conn);
    LOG_INF("Connected to %02x-%02x-%02x-%02x-%02x-%02x",
            addr->a.val[0],addr->a.val[1],addr->a.val[2],addr->a.val[3],addr->a.val[4],addr->a.val[5]);
    cstate = CONNECTED;
    c = conn;
  }
}

static void disconnected(struct bt_conn *conn, uint8_t reason) {
  const bt_addr_le_t *addr = bt_conn_get_dst (conn);
  LOG_INF("Disconnected from %02x-%02x-%02x-%02x-%02x-%02x (reason 0x%02x)",
          addr->a.val[0],addr->a.val[1],addr->a.val[2],addr->a.val[3],addr->a.val[4],addr->a.val[5], reason);
  cstate = DISCONNECTED;
  c = NULL;
  inbuf_end=0;
  inbuf_start=0;
}

static void start_adv(void) {
   int err;

   err = bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
   if (err) {
      LOG_ERR("Advertising failed to start (err %d)", err);
   } else {
      LOG_DBG("Advertising successfully started");
   }
}


BT_CONN_CB_DEFINE(conn_callbacks) = {
    .connected = connected,
    .disconnected = disconnected,
    .recycled = start_adv,
};

static int nus_send(const uint8_t *msg, const size_t len) {
  //if(trace) {
  //  uint8_t hex[len*2+1];
  //  hex[sizeof(hex)-1]=0;
  //  bin2hex(msg,len,hex,sizeof(hex));
  //  printk("sending msg: %s\n", hex);
  //}
  for(size_t ptr = 0;ptr<len;ptr+=20) {
    int err=0;
    const int psize=((len-ptr)>20)?20:(len-ptr);
    do {
      err = bt_nus_send(c, &msg[ptr], psize);
    } while (err == -EAGAIN);
    if(err<0) return err;
  }
  return 0;
}

static int send(const uint8_t *msg, const size_t msg_len) {
  Noise_XK_encap_message_t *encap_msg=NULL;

  encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_STRONG_FORWARD_SECRECY, msg_len, (uint8_t*) msg);
  if(encap_msg==NULL) {
    LOG_ERR("send encap_msg==NULL");
    return -1;
  }

  Noise_XK_rcode res;
  uint8_t *cipher_msg;
  uint32_t cipher_msg_len;

  res = Noise_XK_session_write(encap_msg, session, &cipher_msg_len, &cipher_msg);
  Noise_XK_encap_message_p_free(encap_msg);
  if(!Noise_XK_rcode_is_success(res)) {
    LOG_ERR("failed to wrap encrypted message");
    return -1;
  }

  int err= nus_send(cipher_msg, cipher_msg_len);
  if (cipher_msg_len > 0) free(cipher_msg);
  if(err == -ENOTCONN) {
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return err;
  } else if (err < 0) {
    LOG_ERR("error sending msg: %d", err);
    log_flush();
    k_sleep(K_MSEC(50));
    sys_reboot(SYS_REBOOT_COLD);
  }

  return err;
}

static void zfail(void) {
  send("\x00\x04fail", 6);
  LOG_ERR("zfail");
  log_flush();
  k_sleep(K_MSEC(50));
  sys_reboot(SYS_REBOOT_COLD);
}

static int send_pkt(const uint8_t *msg, const size_t msg_len) {
  uint8_t size[2] = { (msg_len >> 8) & 0xff, msg_len & 0xff } ;
  int ret = send(size, 2);
  if(ret < 0) {
    LOG_ERR("failed to send size of message");
    return ret;
  }
  ret = send(msg, msg_len);
  if(ret < 0) {
    LOG_ERR("failed to send message");
    return ret;
  }
  return 0;
}

int read(size_t size, uint8_t **buf) {
  //if(trace) printk("reading %d\n", size);
  int64_t timeout = 3;
  int64_t start = k_uptime_get();
  size_t plen = 0;
  //if(trace) printk("s: %d, e: %d\n", inbuf_start, inbuf_end);
  while(1) {
    if(cstate!=CONNECTED) return -ENOTCONN;
    if (plen == 0 && inbuf_end-inbuf_start>2) {
      //if(trace) printk("plen = ib[0]: %02x ib[1]: %02x\n", inbuf[inbuf_start], inbuf[inbuf_start+1]);
      plen = (inbuf[inbuf_start]<<8 | inbuf[inbuf_start+1]);
      if(plen >= sizeof(inbuf) - inbuf_start) return -EOVERFLOW;
    }
    if(size!=0) {
      if(inbuf_end-inbuf_start>=size+2+16) {
        if(plen==0 || plen!=size+16) {
          LOG_ERR("E plen: %d, size+16 = %d", plen, size+16);
          return -EMSGSIZE;
        }
        break;
      }
    } else {
      if(plen > 0 && plen <= inbuf_end-inbuf_start) {
        size = plen - 16;
        break;
      }
    }
    int64_t startcopy=start;
    if( k_uptime_delta(&startcopy)/MSEC_PER_SEC > timeout) return -ETIMEDOUT;
    k_sleep(K_MSEC(10));
  }

  //if(trace) {
  //  uint8_t hex[(size+2+16)*2+1];
  //  hex[sizeof(hex)-1]=0;
  //  bin2hex(inbuf+inbuf_start,size+2+16,hex,(size+2+16)*2+1);
  //  printk("rcvd: %d, %d, %s\n", size, plen, hex);
  //}

  Noise_XK_encap_message_t *encap_msg;
  Noise_XK_rcode res;
  uint32_t plain_msg_len;

  res = Noise_XK_session_read(&encap_msg, session, size+16, inbuf+inbuf_start+2);
  if(!Noise_XK_rcode_is_success(res)) {
    LOG_ERR("failed to noise pkt");
    return -1;
  }
  if(!Noise_XK_unpack_message_with_auth_level(&plain_msg_len, buf, NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI, encap_msg)) {
    LOG_ERR("failed to unpack noise pkt");
    Noise_XK_encap_message_p_free(encap_msg);
    return -1;
  }
  Noise_XK_encap_message_p_free(encap_msg);
  if(plain_msg_len!=size) {
    LOG_ERR("pml != s : %d != %d", plain_msg_len, size);
    return -EMSGSIZE;
  }

  //if(trace) printk("unwrapped message of size %d\n", plain_msg_len);

  inbuf_start += plen+2;
  if(inbuf_start == inbuf_end) {
    inbuf_start=0;
    inbuf_end=0;
  } else if(inbuf_start > inbuf_end) return -EINVAL;

  return plain_msg_len;
}

static int setup_noise_connection(void) {
  LOG_INF("trying to establish connection");
  const uint8_t dst[]="klutshnik ble tle";
  const uint8_t noise_name[]="klutshnik server 1";
  const uint8_t srlz_key[AEAD_KEY_SIZE] = {0};
  dev = Noise_XK_device_create(sizeof(dst)-1, dst, noise_name, srlz_key, server_sk);
  if (!Noise_XK_device_add_peer(dev, (uint8_t*) "klutshnik client 1", client_pk)) {
     LOG_ERR("Failed to add client key to noise device");
     return -1;
  }
  session = Noise_XK_session_create_responder(dev);
  if(!session) {
     LOG_ERR("Failed to create noise session");
     Noise_XK_device_free(dev);
     return -1;
  }

  while(cstate!=CONNECTED);
  while(cstate==CONNECTED && inbuf_end!=48) k_sleep(K_MSEC(10));
  if(cstate!=CONNECTED) {
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return ENOTCONN;
  }

  //if(trace) {
  //  uint8_t hex[48*2+1];
  //  hex[sizeof(hex)-1]=0;
  //  bin2hex(inbuf,48,hex,48*2+1);
  //  printk("msg1: %s\n", hex);
  //}
  inbuf_end=0;

  Noise_XK_encap_message_t *encap_msg;
  Noise_XK_rcode res;
  uint8_t *cipher_msg;
  uint32_t cipher_msg_len;
  uint8_t *plain_msg;
  uint32_t plain_msg_len;

  res = Noise_XK_session_read(&encap_msg, session, 48, inbuf);
  if(!Noise_XK_rcode_is_success(res)) {
    LOG_ERR("failed to noise read the handshake init msg");
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return -1;
  }
  if(!Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg, NOISE_XK_AUTH_ZERO, encap_msg)) {
    LOG_ERR("failed to unpack noise handshake init msg");
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    Noise_XK_encap_message_p_free(encap_msg);
    return -1;
  }
  Noise_XK_encap_message_p_free(encap_msg);
  if (plain_msg_len > 0) free(plain_msg);

  encap_msg = Noise_XK_pack_message_with_conf_level(NOISE_XK_CONF_ZERO, 0, NULL);
  res = Noise_XK_session_write(encap_msg, session, &cipher_msg_len, &cipher_msg);
  Noise_XK_encap_message_p_free(encap_msg);
  if(!Noise_XK_rcode_is_success(res)) {
    LOG_ERR("failed to create noise handshake response");
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return -1;
  }

  int err= nus_send(cipher_msg, cipher_msg_len);
  if (cipher_msg_len > 0) free(cipher_msg);
  if(err == -ENOTCONN) {
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return err;
  } else if (err < 0) {
    // fails in subsys/bluetooth/host/gatt.c:2550 calling bt_att_create_pdu(conn, BT_ATT_OP_NOTIFY, sizeof(*nfy) + params->len);
    // which is in subsys/bluetooth/host/att.c:3043
    LOG_ERR("error sending handshake: %d", err);
    log_flush();
    k_sleep(K_MSEC(50));
    sys_reboot(SYS_REBOOT_COLD);
  }

  while(cstate==CONNECTED && inbuf_end!=64) k_sleep(K_MSEC(10));
  if(cstate!=CONNECTED) return ENOTCONN;
  inbuf_end=0;

  //if(trace) {
  //  uint8_t hex[64*2+1];
  //  hex[sizeof(hex)-1]=0;
  //  bin2hex(inbuf,64,hex,sizeof(hex));
  //  printk("msg2: %s\n", hex);
  //}
  res = Noise_XK_session_read(&encap_msg, session, 64, inbuf);
  if(!Noise_XK_rcode_is_success(res)) {
    LOG_ERR("failed to noise read the handshake final msg");
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return -1;
  }
  if(!Noise_XK_unpack_message_with_auth_level(&plain_msg_len, &plain_msg, NOISE_XK_AUTH_KNOWN_SENDER_NO_KCI, encap_msg)) {
    LOG_ERR("failed to unpack noise handshake final msg");
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    Noise_XK_encap_message_p_free(encap_msg);
    return -1;
  }
  Noise_XK_encap_message_p_free(encap_msg);
  if (plain_msg_len > 0) free(plain_msg);

  LOG_INF("Noise channel setup complete");
  return 0;
}

static void reset_ble(void) {
  int err;
  // try switching it off and on again.
  err = bt_le_adv_stop();
  if(err) {
    LOG_ERR("failed to stop advertising: %d\nrebooting...", err);
    log_flush();
    k_sleep(K_MSEC(50));
    sys_reboot(SYS_REBOOT_COLD);
  }
  err = bt_disable();
  if(err) {
    LOG_ERR("failed to disable bt: %d\nrebooting...", err);
    log_flush();
    k_sleep(K_MSEC(50));
    sys_reboot(SYS_REBOOT_COLD);
  }
  inbuf_end=0;
  inbuf_start=0;
  cstate=DISCONNECTED;
  // start again
  err = bt_enable(NULL);
  if (err) {
    LOG_ERR("Failed to enable bluetooth: %d\nrebooting...", err);
    log_flush();
    k_sleep(K_MSEC(50));
    sys_reboot(SYS_REBOOT_COLD);
  }
  start_adv();
}

static int store(const CFG *cfg, const uint8_t recid[crypto_generichash_BYTES], const uint8_t *fieldid,
                 const size_t data_len, const uint8_t data[data_len], const int new) {
  char fname[MAX_PATH_LEN];
  snprintf(fname, sizeof(fname), "%s/data", mountpoint->mnt_point);

  int rc, ret;
  // check if record exists
  struct fs_dirent dirent;

  rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    if(rc != -ENOENT) {
      LOG_ERR("FAIL: stat %s: %d", fname, rc);
      return rc;
    }
    fs_mkdir(fname);
  }

  uint8_t local_id[crypto_generichash_BYTES];
  crypto_generichash(local_id,sizeof local_id,recid,crypto_generichash_BYTES,cfg->rec_salt,32);

  uint8_t hexid[sizeof(local_id)*2+1];
  hexid[sizeof(hexid)-1]=0;
  bin2hex(local_id,sizeof(local_id),hexid,sizeof(hexid));

  snprintf(fname, sizeof(fname), "%s/data/%s", mountpoint->mnt_point, hexid);

  rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    if(rc != -ENOENT) {
      LOG_ERR("FAIL: stat %s: %d", fname, rc);
      return rc;
    }
    fs_mkdir(fname);
  } else {
    if(dirent.type != FS_DIR_ENTRY_DIR) return -ENOTDIR;
    if(new) return -EEXIST;
  }

  snprintf(fname, sizeof(fname), "%s/data/%s/%s", mountpoint->mnt_point, hexid, fieldid);

  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, fname, FS_O_CREATE | FS_O_WRITE | FS_O_TRUNC);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", fname, rc);
    return rc;
  }

  rc = fs_write(&file, data, data_len);
  if (rc < 0) {
    LOG_ERR("FAIL: write %s: %d", fname, rc);
  }

  ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", fname, ret);
    return ret;
  }
  return (rc < 0 ? rc : 0);
}

static int getfield(const CFG *cfg, const uint8_t recid[crypto_generichash_BYTES],
                    const uint8_t *fieldid,
                    const size_t data_len, uint8_t data[data_len]) {
  int rc, ret;
  struct fs_dirent dirent;
  uint8_t local_id[crypto_generichash_BYTES];
  crypto_generichash(local_id,sizeof local_id,recid,crypto_generichash_BYTES,cfg->rec_salt,32);
  uint8_t hexid[sizeof(local_id)*2+1];
  hexid[sizeof(hexid)-1]=0;
  bin2hex(local_id,sizeof(local_id),hexid,sizeof(hexid));

  char fname[MAX_PATH_LEN];
  snprintf(fname, sizeof(fname), "%s/data/%s", mountpoint->mnt_point, hexid);

  rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    LOG_ERR("FAIL: stat %s: %d", fname, rc);
    return rc;
  } else {
    if(dirent.type != FS_DIR_ENTRY_DIR) {
      LOG_ERR("E error %s is not a directory", fname);
      return -ENOTDIR;
    }
  }

  snprintf(fname, sizeof(fname), "%s/data/%s/%s", mountpoint->mnt_point, hexid, fieldid);

  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, fname, FS_O_READ);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", fname, rc);
    return rc;
  }

  rc = fs_read(&file, data, data_len);
  if (rc < 0) {
    LOG_ERR("FAIL: read %s: %d", fname, rc);
    return rc;
  }
  if(rc<data_len) {
    //printk("E error short read, only %d instead of requested %d bytes read from %s\n", rc, data_len, fname);
    LOG_ERR("E error short read, only %d instead of requested %d bytes read from %s", rc, data_len, fname);
    return -ENODATA;
  }

  ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", fname, ret);
    return ret;
  }
  return (rc < 0 ? rc : 0);
}

static int getperm(CFG *cfg,
                   const uint8_t recid[crypto_generichash_BYTES],
                   const uint8_t pk[crypto_sign_PUBLICKEYBYTES],
                   const uint8_t owner[crypto_sign_PUBLICKEYBYTES]) {
  int rc, ret;
  struct fs_dirent dirent;
  uint8_t local_id[crypto_generichash_BYTES];
  crypto_generichash(local_id,sizeof local_id,recid,crypto_generichash_BYTES,cfg->rec_salt,32);
  uint8_t hexid[sizeof(local_id)*2+1];
  hexid[sizeof(hexid)-1]=0;
  bin2hex(local_id,sizeof(local_id),hexid,sizeof(hexid));

  char fname[MAX_PATH_LEN];
  snprintf(fname, sizeof(fname), "%s/data/%s", mountpoint->mnt_point, hexid);

  rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    LOG_ERR("FAIL: stat %s: %d", fname, rc);
    return rc;
  } else {
    if(dirent.type != FS_DIR_ENTRY_DIR) {
      LOG_ERR("E error %s is not a directory", fname);
      return -ENOTDIR;
    }
  }

  snprintf(fname, sizeof(fname), "%s/data/%s/auth", mountpoint->mnt_point, hexid);
  rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    LOG_ERR("FAIL: stat %s: %d", fname, rc);
    return rc;
  } else {
    if(dirent.type != FS_DIR_ENTRY_FILE) {
      LOG_ERR("E error %s is not a file", fname);
      return -EISDIR;
    }
  }

  uint8_t authbuf[dirent.size];

  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, fname, FS_O_READ);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", fname, rc);
    return rc;
  }

  rc = fs_read(&file, authbuf, dirent.size);
  if (rc < 0) {
    LOG_ERR("FAIL: read %s: %d", fname, rc);
    return rc;
  }
  if(rc<dirent.size) {
    LOG_ERR("E error short read, only %d instead of requested %d bytes read from %s", rc, dirent.size, fname);
    return -ENODATA;
  }

  ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", fname, ret);
    return ret;
  }

  if(0!=crypto_sign_verify_detached(authbuf, authbuf + crypto_sign_BYTES, dirent.size - crypto_sign_BYTES, owner)) {
    LOG_ERR("E auth data not signed by owner");
    zfail();
  }

  size_t ptr = crypto_sign_BYTES;
  while(ptr < dirent.size) {
    uint8_t *_pk = authbuf + ptr;
    ptr += crypto_sign_PUBLICKEYBYTES;
    if(0==memcmp(_pk, pk, crypto_sign_PUBLICKEYBYTES)) {
      return authbuf[ptr];
    }
    ptr++;
  }
  return -EACCES;
}

static int auth(const CFG *cfg, const KlutshnikOp op, uint8_t pk[crypto_sign_PUBLICKEYBYTES],
                const size_t reqbuf_len, const uint8_t reqbuf[reqbuf_len]) {
  uint8_t _signed[reqbuf_len + 32];
  const uint8_t *nonce = _signed + reqbuf_len;
  memcpy(_signed, reqbuf, reqbuf_len);

  const struct device *rng_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
  if (!device_is_ready(rng_dev)) {
    LOG_ERR("error: random device not ready");
    return -EAGAIN;
  }
  entropy_get_entropy(rng_dev, (char *) nonce, 32);
  int ret = send_pkt(nonce, 32);
  if(ret < 0) {
    LOG_ERR("failed to send auth nonce: %d", ret);
    return ret;
  }

  uint8_t perm;
  switch(op) {
  case OP_DECRYPT: { perm = DECRYPT_perm; break; }
  case OP_DELETE:  { perm = DELETE_perm; break; }
  case OP_MODAUTH: { perm = OWNER_perm; break; }
  case OP_UPDATE: { perm = UPDATE_perm; break; }
  case OP_REFRESH: { perm = OWNER_perm | UPDATE_perm | DECRYPT_perm; break; }
  default: { return -EINVAL; }
  }

  uint8_t *sig;
  ret = read(crypto_sign_BYTES+2,&sig);
  if(ret < 0) {
    LOG_ERR("failed to read auth sig: %d", ret);
    return ret;
  }

  uint8_t owner[crypto_sign_PUBLICKEYBYTES];
  ret = getfield(cfg, reqbuf+2, "owner", sizeof(owner), owner);
  if(ret < 0) {
    LOG_ERR("E failed to load owners pubkey: %d", ret);
    zfail();
  }
  bool authorized = false;
  if(op == OP_MODAUTH) {
    memcpy(pk, owner, sizeof owner);
    authorized = true;
  } else {
    ret = getperm(cfg,reqbuf+2,pk,owner);
    if(ret > 0 && ((ret & perm) != 0)) authorized = true;
  }

  if(0!=crypto_sign_verify_detached(sig+2, _signed, sizeof(_signed), pk)) {
    LOG_ERR("E auth data not signed by owner");
    zfail();
  }

  uint8_t hex[crypto_sign_PUBLICKEYBYTES*2+1];
  hex[sizeof(hex)-1]=0;
  bin2hex(pk,crypto_sign_PUBLICKEYBYTES,hex,sizeof(hex));

  if(!authorized) {
    LOG_ERR("unauthorized: %s", hex);
    zfail();
  }

  LOG_INF("authorized: %s", hex);
  return 0;
}


int toprf_update(const CFG *cfg, const UpdateReq *req) {
  int ret=0;

  if(0!=auth(cfg, OP_UPDATE, req->pk, sizeof(UpdateReq), (uint8_t*) req)) {
    LOG_ERR("failed to authenticate");
    zfail();
  }

  TOPRF_Update_PeerState ctx;

  uint8_t pkid[toprf_keyid_SIZE];
  uint8_t stp_ltpks[crypto_sign_PUBLICKEYBYTES];
  ret = toprf_update_start_peer(&ctx, dkg_freshness_TIMEOUT,
                                cfg->ltsig_sk, cfg->noise_sk,
                                (DKG_Message*) req->msg0,
                                pkid, stp_ltpks);
  if(0!=ret) {
    LOG_ERR("E toprf-update-start failed: %d", ret);
    zfail();
  }

  if(0!=memcmp(stp_ltpks, req->pk, crypto_sign_PUBLICKEYBYTES)) {
    LOG_ERR("E stp_ltpk from client != authorized pk in request. abort");
    zfail();
  }

  if(0!=memcmp(pkid, req->id, crypto_sign_PUBLICKEYBYTES)) {
    LOG_ERR("E pkid from client != authorized req.id in request. abort");
    zfail();
  }

  uint8_t params[2];
  ret = getfield(cfg, req->id, "params", sizeof(params), params);
  if(ret < 0) {
    LOG_ERR("E failed to load params: %d", ret);
    zfail();
  }
  LOG_INF("params are n: %d, t: %d", params[0], params[1]);
  ctx.n=params[0];
  ctx.t=params[1];
  uint8_t n = params[0], t=params[1];
  const uint8_t dealers = (t-1)*2 + 1;

  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  memcpy(lt_pks[0], stp_ltpks, crypto_sign_PUBLICKEYBYTES);

  ret = getfield(cfg, req->id, "sigkeys", crypto_sign_PUBLICKEYBYTES*n, lt_pks[1]);
  if(ret < 0) {
    LOG_ERR("E failed to load sigkeys: %d", ret);
    zfail();
  }

  uint8_t peers_noise_pks[n][crypto_scalarmult_BYTES];
  ret = getfield(cfg, req->id, "noisekeys", crypto_scalarmult_BYTES*n, peers_noise_pks[0]);
  if(ret < 0) {
    LOG_ERR("E failed to load noisekeys: %d", ret);
    zfail();
  }

  TOPRF_Share k0_share[2] = {0};
  ret = getfield(cfg, req->id, "share", sizeof(k0_share), (uint8_t*) k0_share);
  if(ret < 0) {
    LOG_ERR("E failed to load share: %d", ret);
    zfail();
  }
  const uint8_t self = k0_share[0].index;

  uint8_t k0_commitments[n][crypto_core_ristretto255_BYTES];
  ret = getfield(cfg, req->id, "commitments", sizeof(k0_commitments), (uint8_t*) k0_commitments);
  if(ret < 0) {
    LOG_ERR("E failed to load commitments: %d", ret);
    zfail();
  }

  uint32_t epoch;
  ret = getfield(cfg, req->id, "epoch", sizeof(epoch), (uint8_t*) &epoch);
  if(ret < 0) {
    LOG_ERR("E failed to load epoch: %d", ret);
    zfail();
  }

  uint64_t now = k_uptime_seconds();
  ref_time = ntohll(((DKG_Message*) req->msg0)->ts) - now;

  LOG_INF("[T] allocating memory for peers state..");
  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  Noise_XK_session_t *noise_outs[n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n];
  memset(noise_ins, 0, sizeof noise_ins);

  TOPRF_Share pshares[n][2];
  memset(pshares, 0, sizeof pshares);
  uint8_t p_commitments[n*n][crypto_core_ristretto255_BYTES];
  memset(p_commitments, 0, sizeof p_commitments);
  uint8_t p_commitments_hashes[n][toprf_update_commitment_HASHBYTES];
  memset(p_commitments_hashes, 0, sizeof p_commitments_hashes);
  uint8_t peers_p_share_macs[n*n][crypto_auth_hmacsha256_BYTES];
  memset(peers_p_share_macs, 0, sizeof peers_p_share_macs);
  uint16_t peer_p_complaints[n*n];
  memset(peer_p_complaints, 0, sizeof peer_p_complaints);
  uint8_t peer_my_p_complaints[n];
  memset(peer_my_p_complaints, 0, sizeof peer_my_p_complaints);

  uint8_t encrypted_shares[n][noise_xk_handshake3_SIZE + toprf_update_encrypted_shares_SIZE];
  memset(encrypted_shares, 0, sizeof encrypted_shares);

  uint64_t peer_last_ts[n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  uint8_t lambdas[dealers][crypto_core_ristretto255_SCALARBYTES];

  TOPRF_Share k0p_shares[dealers][2];
  uint8_t k0p_commitments[dealers*(n+1)][crypto_core_ristretto255_BYTES];
  uint8_t zk_challenge_nonce_commitments[n][crypto_scalarmult_ristretto255_BYTES];
  uint8_t zk_challenge_nonces[n][2][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_commitments[dealers][3][crypto_scalarmult_ristretto255_SCALARBYTES];
  uint8_t zk_challenge_e_i[dealers][crypto_scalarmult_ristretto255_SCALARBYTES];
  TOPRF_Update_Cheater peer_cheaters[n*n - 1];
  memset(peer_cheaters,0,sizeof(peer_cheaters));

  LOG_INF(" done");

  // in a real deployment peers do not share the same pks buffers
  if(0!=toprf_update_peer_set_bufs(&ctx, self, n, t, k0_share,
                                   &k0_commitments,
                                   &lt_pks, &peers_noise_pks,
                                   &noise_outs, &noise_ins,
                                   &pshares,
                                   &p_commitments,
                                   &p_commitments_hashes,
                                   &peers_p_share_macs,
                                   &encrypted_shares,
                                   &peer_cheaters, sizeof(peer_cheaters) / sizeof(TOPRF_Update_Cheater) / n,
                                   &lambdas,
                                   &k0p_shares,
                                   &k0p_commitments,
                                   &zk_challenge_nonce_commitments,
                                   &zk_challenge_nonces,
                                   &zk_challenge_commitments,
                                   &zk_challenge_e_i,
                                   peer_p_complaints,
                                   peer_my_p_complaints,
                                   peer_last_ts)) {
    LOG_ERR("invalid n/t parameters. aborting");
    zfail();
  }

  while(toprf_update_peer_not_done(&ctx)) {
    const TOPRF_Update_Peer_Steps curstep = ctx.step;

    const size_t peer_in_size = toprf_update_peer_input_size(&ctx);
    uint8_t *peer_in = NULL;

    if(peer_in_size>0) {
      ret = read(peer_in_size+2, &peer_in);
      if(ret < 0) {
        LOG_ERR("error reading packet for step %d: %d", curstep, ret);
        zfail();
      }
    }

    // 0sized vla meh
    const size_t peer_out_size = toprf_update_peer_output_size(&ctx);
    uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
    if(peer_out_size==0) peers_out = NULL;
    else peers_out = peers_out_buf;

    LOG_INF("I toprf-update step %d, in: %d, out: %d", curstep, peer_in_size, peer_out_size);

    ret = toprf_update_peer_next(&ctx,
                                 peer_in+2, peer_in_size,
                                 peers_out, peer_out_size);
    if(peer_in!=NULL) free(peer_in);
    if(0!=ret) {
      // clean up peers
      LOG_ERR("peer_next, step %d returned %d", curstep, ret);
      toprf_update_peer_free(&ctx);
      zfail();
    }
    if(peer_out_size>0) {
      //if(trace) {
      //  uint8_t hex[peer_out_size*2+1];
      //  hex[sizeof(hex)-1]=0;
      //  bin2hex(peers_out_buf,peer_out_size,hex,sizeof(hex));
      //  printk("peers_out_buf %s\n", hex);
      //}
      //printk("send: ");
      ret = send_pkt(peers_out_buf, peer_out_size);
      if(ret < 0) {
        LOG_ERR("failed to send message for step %d", curstep);
        return ret;
      }
      //printk("ok\n");
    }
  }

  struct {
    uint32_t epoch;
    uint8_t pki[TOPRF_Share_BYTES];
  } __attribute__((__packed__)) response;
  response.pki[0] = ctx.k0p_share[0].index;

  if(0!=crypto_scalarmult_ristretto255_base(&response.pki[1], ctx.k0p_share[0].value)) {
    LOG_ERR("generated invalid share");
    return -1;
  }

  LOG_INF("storing record");

  ret = store(cfg, req->id, "share", TOPRF_Share_BYTES*2, (const uint8_t*) ctx.k0p_share, 0);
  if(ret!=0) {
    LOG_ERR("failed to store share: %d", ret);
    return ret;
  }
  ret = store(cfg, req->id, "commitments", crypto_scalarmult_ristretto255_BYTES*n, (const uint8_t*) ctx.p_commitments, 0);
  if(ret!=0) {
    LOG_ERR("failed to store commitments: %d", ret);
    return ret;
  }
  epoch++;
  ret = store(cfg, req->id, "epoch", sizeof epoch, (uint8_t*) &epoch, 0);
  if(ret!=0) {
    LOG_ERR("failed to store share epoch: %d", ret);
    return ret;
  }

  response.epoch = htonl(epoch);

  LOG_INF("sending epoch+pki");
  ret = send((uint8_t*) &response, sizeof(response));
  if(ret < 0) {
    LOG_ERR("failed to send final epoch+pki");
    return ret;
  }

  return ret;
}

//typedef struct {
//  size_t len;
//  uint8_t (*sig_pks)[][crypto_sign_PUBLICKEYBYTES];
//  uint8_t (*noise_pks)[][crypto_scalarmult_BYTES];
//} Keyloader_CB_Arg;

int keyloader_cb(const uint8_t id[crypto_generichash_BYTES], void *arg, uint8_t sigpk[crypto_sign_PUBLICKEYBYTES], uint8_t noise_pk[crypto_scalarmult_BYTES]) {
  //Keyloader_CB_Arg *args = (Keyloader_CB_Arg *) arg;
  //uint8_t pkhash[crypto_generichash_BYTES];
  //dump(id, crypto_generichash_BYTES, "loading keys for keyid");
  for(unsigned i=0;i<6 /*todo get from config*/;i++) {
    //crypto_generichash(pkhash,sizeof pkhash,(*args->sig_pks)[i+1],crypto_sign_PUBLICKEYBYTES,NULL,0);
    //if(memcmp(pkhash, id, sizeof pkhash) == 0) {
    if(memcmp(authkeys[i].keyid, id, crypto_generichash_BYTES) == 0) {
      //memcpy(sigpk, (*args->sig_pks)[i+1], crypto_sign_PUBLICKEYBYTES);
      //memcpy(noise_pk, (*args->noise_pks)[i], crypto_scalarmult_BYTES);
      memcpy(sigpk, authkeys[i].ltsig, crypto_sign_PUBLICKEYBYTES);
      memcpy(noise_pk, authkeys[i].noise, crypto_scalarmult_BYTES);
      return 0;
    }
  }
  if(trace) {
    uint8_t hex[crypto_generichash_BYTES*2+1];
    hex[sizeof(hex)-1]=0;
    bin2hex(id,crypto_generichash_BYTES,hex,sizeof(hex));
    LOG_ERR("E stp-dkg: no auth key found for keyid: %s", hex);
  }
  return 1;
}

static int stp_dkg(const CFG *cfg, const CreateReq *req) {
  int ret=0;

  STP_DKG_PeerState ctx;
  uint8_t stp_ltpk[crypto_sign_PUBLICKEYBYTES];
  ret = stp_dkg_start_peer(&ctx, dkg_freshness_TIMEOUT,
                           cfg->ltsig_sk,
                           cfg->noise_sk,
                           (DKG_Message*) req->msg0,
                           stp_ltpk);
  if(0 != ret) {
    LOG_ERR("E start failed: %d. abort.", ret);
    zfail();
  }

  uint64_t now = k_uptime_seconds();
  ref_time = ntohll(((DKG_Message*) req->msg0)->ts) - now;
  //if(trace) printk("setting reftime, now = %lld, ts = %lld, ref_time = %lld\n", now, ntohll(((DKG_Message*) req->msg0)->ts), ref_time);

  const uint8_t n=ctx.n;
  const uint8_t t=ctx.t;

  LOG_INF("[T] allocating memory for peer state..");
  // now that the peer(s) know the value of N, we can allocate buffers
  // to hold all the sig&noise keys, noise sessions, temp shares, commitments
  uint8_t peerids[n][crypto_generichash_BYTES];
  uint8_t lt_pks[n+1][crypto_sign_PUBLICKEYBYTES];
  memcpy(lt_pks[0], stp_ltpk, sizeof(stp_ltpk));
  uint8_t peers_noise_pks[n][crypto_scalarmult_BYTES];
  Noise_XK_session_t *noise_outs[n];
  memset(noise_outs, 0, sizeof noise_outs);
  Noise_XK_session_t *noise_ins[n];
  memset(noise_ins, 0, sizeof noise_ins);
  TOPRF_Share dealer_shares[n][2];
  memset(dealer_shares, 0, sizeof dealer_shares);
  uint8_t encrypted_shares[n][noise_xk_handshake3_SIZE + stp_dkg_encrypted_share_SIZE];
  memset(encrypted_shares,0,sizeof encrypted_shares);
  uint8_t dealer_commitments[n*n][crypto_core_ristretto255_BYTES];
  memset(dealer_commitments, 0, sizeof dealer_commitments);
  uint8_t share_macs[n*n][crypto_auth_hmacsha256_BYTES];
  uint8_t peer_k_commitments[n][crypto_core_ristretto255_BYTES];
  memset(peer_k_commitments, 0, sizeof peer_k_commitments);
  uint8_t commitments_hashes[n][stp_dkg_commitment_HASHBYTES];
  memset(commitments_hashes, 0, sizeof commitments_hashes);
  uint16_t peer_dealer_share_complaints[n*n];
  memset(peer_dealer_share_complaints, 0, sizeof peer_dealer_share_complaints);
  uint8_t peer_my_dealer_share_complaints[n];
  memset(peer_my_dealer_share_complaints, 0, sizeof peer_my_dealer_share_complaints);
  uint64_t peer_last_ts[n];
  memset(peer_last_ts, 0, sizeof peer_last_ts);
  STP_DKG_Cheater peer_cheaters[t*t - 1];
  memset(peer_cheaters,0,sizeof(peer_cheaters));
  //Keyloader_CB_Arg cb_arg = {n, &lt_pks, &peers_noise_pks};

  // in a real deployment peers do not share the same pks buffers
  if(0!=stp_dkg_peer_set_bufs(&ctx, &peerids,
                              &keyloader_cb, NULL, //&cb_arg,
                              &lt_pks,
                              &peers_noise_pks,
                              &noise_outs, &noise_ins,
                              &dealer_shares,
                              &encrypted_shares,
                              &share_macs,
                              &dealer_commitments,
                              &peer_k_commitments,
                              &commitments_hashes,
                              &peer_cheaters, sizeof(peer_cheaters) / sizeof(STP_DKG_Cheater) / n,
                              peer_dealer_share_complaints,
                              peer_my_dealer_share_complaints,
                              peer_last_ts)) {
    LOG_ERR("invalid n/t parameters. aborting");
    zfail();
  }

  while(stp_dkg_peer_not_done(&ctx)) {
    const STP_DKG_Peer_Steps curstep = ctx.step;

    // 0sized vla meh
    const size_t peer_out_size = stp_dkg_peer_output_size(&ctx);
    uint8_t peers_out_buf[peer_out_size==0?1:peer_out_size], *peers_out;
    if(peer_out_size==0) peers_out = NULL;
    else peers_out = peers_out_buf;

    // 0sized vla meh for the last time..
    const size_t peer_in_size = stp_dkg_peer_input_size(&ctx);
    uint8_t *peer_in = NULL;

    if(peer_in_size>0) {
      ret = read(peer_in_size+2, &peer_in);
      if(ret < 0) {
        LOG_ERR("error reading packet for step %d: %d", curstep, ret);
        zfail();
      }
    }
    LOG_INF("I stp_dkg step %d, in: %d, out: %d", curstep, peer_in_size, peer_out_size);

    ret = stp_dkg_peer_next(&ctx,
                            peer_in+2, peer_in_size,
                            peers_out, peer_out_size);

    if(peer_in!=NULL) free(peer_in);
    if(0!=ret) {
      // clean up peers
      LOG_ERR("peer_next returned %d", ret);
      stp_dkg_peer_free(&ctx);
      zfail();
    }
    if(peer_out_size>0) {
      ret = send_pkt(peers_out_buf, peer_out_size);
      if(ret < 0) {
        LOG_ERR("failed to send message for step %d", curstep);
        return ret;
      }
    }
  }

  uint8_t pki[TOPRF_Share_BYTES];
  pki[0] = ctx.share[0].index;
  if(0!=crypto_scalarmult_ristretto255_base(&pki[1], ctx.share[0].value)) {
    LOG_ERR("generated invalid share");
    return -1;
  }

  LOG_INF("storing record");

  ret = store(cfg, req->id, "share", TOPRF_Share_BYTES*2, (const uint8_t*) &ctx.share, 1);
  if(ret!=0) {
    LOG_ERR("failed to store share: %d", ret);
    return ret;
  }
  ret = store(cfg, req->id, "commitments", sizeof(peer_k_commitments), (const uint8_t*) peer_k_commitments, 0);
  if(ret!=0) {
    LOG_ERR("failed to store commitments: %d", ret);
    return ret;
  }
  ret = store(cfg, req->id, "sigkeys", n*crypto_sign_PUBLICKEYBYTES, (const uint8_t*) &lt_pks[1], 0);
  if(ret!=0) {
    LOG_ERR("failed to store long-term sigkeys: %d", ret);
    return ret;
  }
  ret = store(cfg, req->id, "noisekeys", sizeof peers_noise_pks, (const uint8_t*) peers_noise_pks, 0);
  if(ret!=0) {
    LOG_ERR("failed to store noise pubkeys: %d", ret);
    return ret;
  }
  const uint8_t params[2] = { n, t };
  ret = store(cfg, req->id, "params", sizeof params, params, 0);
  if(ret!=0) {
    LOG_ERR("failed to store share setup: %d", ret);
    return ret;
  }
  ret = store(cfg, req->id, "owner", crypto_sign_PUBLICKEYBYTES, lt_pks[0], 0);
  if(ret!=0) {
    LOG_ERR("failed to store owner sig pubkey: %d", ret);
    return ret;
  }
  const uint8_t epoch[4] = {0};
  ret = store(cfg, req->id, "epoch", sizeof epoch, epoch, 0);
  if(ret!=0) {
    LOG_ERR("failed to store share epoch: %d", ret);
    return ret;
  }

  LOG_INF("sending pki");
  ret = send(pki, TOPRF_Share_BYTES);
  if(ret < 0) {
    LOG_ERR("failed to send pki");
    return ret;
  }

  LOG_INF("receiving auth_buf");
  uint8_t *auth_buf;
  ret = read(0,&auth_buf);
  if(ret < 0) {
    LOG_ERR("error reading packet: %d", ret);
    zfail();
  }
  LOG_INF("verifying auth_buf");
  // todo authbuf has probably len prefixed, as it is send_pkt-ed..
  if(0!=crypto_sign_verify_detached(auth_buf + 2, auth_buf + 2 + crypto_sign_BYTES,ret - 2 - crypto_sign_BYTES,stp_ltpk)) {
    LOG_ERR("E auth data not signed by owner");
    zfail();
  }

  LOG_INF("storing auth_buf");
  ret = store(cfg, req->id, "auth", ret - 2, auth_buf + 2, 0);
  free(auth_buf);
  if(ret < 0) {
    LOG_ERR("E failed to store auth");
    return ret;
  }

  return 0;
}

static int rmdir(const char *path) {
  LOG_INF("recursively deleting %s", path);
  struct fs_dir_t dirp;
  fs_dir_t_init(&dirp);

  struct fs_dirent dirent;
  int ret = fs_opendir(&dirp, path);
  if (ret) {
    LOG_ERR("Error opening dir %s [%d]", path, ret);
    return ret;
  }

  for (;;) {
    /* Verify fs_readdir() */
    ret = fs_readdir(&dirp, &dirent);

    /* dirent.name[0] == 0 means end-of-dir */
    if (ret || dirent.name[0] == 0) {
      if (ret < 0) {
        LOG_ERR("Error reading dir [%d]", ret);
      }
      break;
    }

    char fname[MAX_PATH_LEN];
    snprintf(fname, sizeof(fname), "%s/%s", path, dirent.name);

    if (dirent.type == FS_DIR_ENTRY_DIR) {
      LOG_WRN("W is a dir: %s", fname);
    }
    ret = fs_unlink(fname);
    if(ret<0) {
      LOG_ERR("ERROR unlinking: %s", fname);
    }
  }

  /* Verify fs_closedir() */
  fs_closedir(&dirp);

  fs_unlink(path);
  return 0;
}

static int decrypt(const CFG *cfg, const DecryptReq *req) {
  int rc, ret;
  if(0!=auth(cfg, OP_DECRYPT, req->pk, sizeof(DecryptReq), (uint8_t*) req)) {
    LOG_ERR("failed to authenticate");
    zfail();
  }

  TOPRF_Share share[2];
  ret = getfield(cfg,req->id,"share",sizeof(share),(uint8_t*) &share);
  if(ret < 0) {
    LOG_ERR("E failed to load share: %d", ret);
    return ret;
  }

  if(0==crypto_core_ristretto255_is_valid_point(req->alpha)) zfail();
  TOPRF_Share response[2];
  response[0].index=share[0].index;
  response[1].index=share[0].index;
  if(0!=crypto_scalarmult_ristretto255(response[0].value, share[0].value, req->alpha)) zfail();

  if(0==crypto_core_ristretto255_is_valid_point(req->verifier)) zfail();
  if(0!=crypto_scalarmult_ristretto255(response[1].value, share[0].value, req->verifier)) zfail();

  ret = send((uint8_t*) &response, sizeof(response));
  if(ret < 0) {
    LOG_ERR("failed to send beta+verifier");
    return ret;
  }

  uint8_t hex[sizeof(req->id)*2+1];
  hex[sizeof(hex)-1]=0;
  bin2hex(req->id,sizeof(req->id),hex,sizeof(hex));
  LOG_INF("decrypt for %s", hex);

  return 0;
}

static int modauth(const CFG *cfg, const ModAuthReq *req) {
  int rc, ret;
  uint8_t pk[crypto_sign_PUBLICKEYBYTES];
  if(0!=auth(cfg, OP_MODAUTH, pk, sizeof(ModAuthReq), (uint8_t*) req)) {
    LOG_ERR("failed to authenticate");
    zfail();
  }

  struct fs_dirent dirent;
  uint8_t local_id[crypto_generichash_BYTES];
  crypto_generichash(local_id,sizeof local_id,req->id,crypto_generichash_BYTES,cfg->rec_salt,32);
  uint8_t hexid[sizeof(local_id)*2+1];
  hexid[sizeof(hexid)-1]=0;
  bin2hex(local_id,sizeof(local_id),hexid,sizeof(hexid));

  char fname[MAX_PATH_LEN];
  snprintf(fname, sizeof(fname), "%s/data/%s/auth", mountpoint->mnt_point, hexid);

  rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    LOG_ERR("FAIL: stat %s: %d", fname, rc);
    return rc;
  } else {
    if(dirent.type != FS_DIR_ENTRY_FILE) {
      LOG_ERR("E error %s is not a file", fname);
      return -EISDIR;
    }
  }

  uint8_t authbuf[dirent.size];

  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, fname, FS_O_READ);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", fname, rc);
    return rc;
  }

  rc = fs_read(&file, authbuf, dirent.size);
  if (rc < 0) {
    LOG_ERR("FAIL: read %s: %d", fname, rc);
    return rc;
  }
  if(rc!=dirent.size) {
    LOG_ERR("E error short read, only %d instead of requested %d bytes read from %s", rc, dirent.size, fname);
    return -ENODATA;
  }

  ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", fname, ret);
    return ret;
  }

  ret = send_pkt(authbuf, dirent.size);
  if(ret < 0) {
    LOG_ERR("failed to send authbuf");
    return ret;
  }

  if(req->readonly) {
    LOG_INF("%s list auth success", hexid);
    return 0;
  }

  uint8_t *authbuf2;
  ret = read(0, &authbuf2);
  if(ret < 0) {
    LOG_ERR("failed to read new authbuf: %d", ret);
    return ret;
  }

  if(0!=crypto_sign_verify_detached(authbuf2 + 2, authbuf2 + 2 + crypto_sign_BYTES, ret - 2 - crypto_sign_BYTES, pk)) {
    LOG_ERR("E new auth data not signed by owner");
    zfail();
  }

  ret = store(cfg, req->id, "auth", ret - 2, authbuf2 + 2, 0);
  free(authbuf2);
  if(ret < 0) {
    LOG_ERR("E failed to store auth");
    return ret;
  }

  LOG_INF("%s mod auth success", hexid);

  return 0;
}

static int refresh(const CFG *cfg, const RefreshReq *req) {
  int rc, ret;
  if(0!=auth(cfg, OP_REFRESH, req->pk, sizeof(RefreshReq), (uint8_t*) req)) {
    LOG_ERR("failed to authenticate");
    zfail();
  }

  TOPRF_Share share[2];
  ret = getfield(cfg,req->id,"share",sizeof(share),(uint8_t*) &share);
  if(ret < 0) {
    LOG_ERR("E failed to load share: %d", ret);
    return ret;
  }

  struct {
    uint32_t epoch;
    TOPRF_Share pki;
  } __attribute__((__packed__)) response;

  ret = getfield(cfg,req->id,"epoch",sizeof(uint32_t),(uint8_t*) &response.epoch);
  if(ret < 0) {
    LOG_ERR("E failed to load epoch: %d", ret);
    return ret;
  }
  response.epoch=htonl(response.epoch);

  response.pki.index=share[0].index;
  if(0!=crypto_scalarmult_ristretto255_base(response.pki.value, share[0].value)) zfail();

  ret = send((uint8_t*) &response, sizeof(response));
  if(ret < 0) {
    LOG_ERR("failed to send beta+verifier");
    return ret;
  }

  uint8_t hex[sizeof(req->id)*2+1];
  hex[sizeof(hex)-1]=0;
  bin2hex(req->id,sizeof(req->id),hex,sizeof(hex));
  LOG_INF("refresh for %s", hex);

  return 0;
}

static int delete(const CFG *cfg, const DeleteReq *req) {
  int rc, ret;
  if(0!=auth(cfg, OP_DELETE, req->pk, sizeof(DeleteReq), (uint8_t*) req)) {
    LOG_ERR("failed to authenticate");
    zfail();
  }

  char path[MAX_PATH_LEN];
  snprintf(path, sizeof(path), "%s/data", mountpoint->mnt_point);

  // check if record exists
  struct fs_dirent dirent;

  rc = fs_stat(path, &dirent);
  if (rc < 0) {
    if(rc != -ENOENT) {
      LOG_ERR("FAIL: stat %s: %d", path, rc);
      return rc;
    }
    LOG_INF("FAIL: %s doesn't exist", path);
    return 0;
  }

  uint8_t local_id[crypto_generichash_BYTES];
  crypto_generichash(local_id,sizeof local_id,req->id,crypto_generichash_BYTES,cfg->rec_salt,32);

  uint8_t hexid[sizeof(local_id)*2+1];
  hexid[sizeof(hexid)-1]=0;
  bin2hex(local_id,sizeof(local_id),hexid,sizeof(hexid));

  snprintf(path, sizeof(path), "%s/data/%s", mountpoint->mnt_point, hexid);

  rc = fs_stat(path, &dirent);
  if (rc < 0) {
    if(rc != -ENOENT) {
      LOG_ERR("FAIL: stat %s: %d", path, rc);
      return rc;
    }
    LOG_INF("FAIL: %s doesn't exist", path);
    return 0;
  } else {
    if(dirent.type != FS_DIR_ENTRY_DIR) {
      LOG_WRN("W: %s is not a directory", path);
      fs_unlink(path);
      return -ENOTDIR;
    }
  }

  ret = rmdir(path);
  if(ret<0) {
    LOG_ERR("Error rmdir(\"%s\") failed with: %d", path, ret);
    return ret;
  }

  ret = send("ok", 2);
  if(ret < 0) {
    LOG_ERR("failed to send \"ok\"");
    return ret;
  }

  return 0;
}

static int initkey(const char *path, const size_t key_len, uint8_t *key) {
  struct fs_dirent entry;
  if(0 == fs_stat(path, &entry)) {
    LOG_WRN("W %s does exist", path);
    if(entry.size!=key_len) {
      LOG_ERR("%s has invalid size", path);
      fs_unlink(path);
    } else {
      return -EEXIST;
    }
  }

  const struct device *rng_dev = DEVICE_DT_GET(DT_CHOSEN(zephyr_entropy));
  if (!device_is_ready(rng_dev)) {
    LOG_ERR("error: random device not ready");
    return -EAGAIN;
  }
  entropy_get_entropy(rng_dev, (char *)key, key_len);
  crypto_generichash(key,key_len, key,key_len, NULL,0);

  struct fs_file_t file;
  int rc, ret;
  fs_file_t_init(&file);
  rc = fs_open(&file, path, FS_O_CREATE | FS_O_WRITE);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", path, rc);
    return rc;
  }

  rc = fs_write(&file, key, key_len);
  if (rc < 0) {
    LOG_ERR("FAIL: write %s: %d", path, rc);
    goto out;
  }
out:
  ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", path, ret);
    return ret;
  }
  return (rc < 0 ? rc : 0);
}

static int initcfg(CFG *cfg) {
  fs_mkdir("/lfs/cfg");

  int rc;
  rc = initkey("/lfs/cfg/noise_key", 32, cfg->noise_sk);
  if(rc!=0) {
    LOG_ERR("E failed to init noise_sk");
    return rc;
  }
  Noise_XK_dh_secret_to_public(cfg->noise_pk, cfg->noise_sk);

  uint8_t noise_seed[crypto_sign_SEEDBYTES];
  rc = initkey("/lfs/cfg/ltsig_seed", crypto_sign_SEEDBYTES, noise_seed);
  if(rc!=0) {
    LOG_ERR("E failed to init ltsig_seed");
    return rc;
  }
  if(0!=crypto_sign_seed_keypair(cfg->ltsig_pk, cfg->ltsig_sk, noise_seed)) {
    LOG_ERR("E failed to derive ltsig keypair");
    return -1;
  }
  sodium_memzero(noise_seed,sizeof noise_seed);

  rc = initkey("/lfs/cfg/record_salt", 32, cfg->rec_salt);
  if(rc!=0) {
    LOG_ERR("E failed to init record salt");
    return rc;
  }

  return 0;
}

static void printb64(const char* prefix, const size_t buf_len, const uint8_t *buf) {
  size_t olen;
  base64_encode(NULL,0,&olen,buf,buf_len);
  uint8_t b64[olen];
  base64_encode(b64,olen,&olen,buf,buf_len);
  LOG_INF("%s %s", prefix, b64);
}

static int load(const char* path, const size_t buf_len, uint8_t *buf) {
  int rc, ret;
  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, path, FS_O_READ);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", path, rc);
    return rc;
  }
  rc = fs_read(&file, buf, buf_len);
  if (rc < 0) {
    LOG_ERR("FAIL: read %s: %d", path, rc);
    goto out;
  }
  if(rc!=buf_len) {
    LOG_ERR("FAIL: short read only %dB instead of %dB", rc, buf_len);
    return -EINVAL;
  }
out:
  ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", path, ret);
    return ret;
  }

  return (rc < 0 ? rc : 0);
}

static int loadcfg(const char* path, const size_t buf_len, uint8_t *buf) {
  int rc;
  rc=load(path, buf_len, buf);
  if(rc==0) return 0;
  if(rc!=-ENOENT) return -1;
  rc = initkey(path, buf_len, buf);
  if(rc!=0) {
    LOG_ERR("E failed to init %s", path);
    return rc;
  }
  return 0;
}

static int getcfg(CFG *cfg) {
  //fs_unlink("/lfs/cfg/noise_key");
  //fs_unlink("/lfs/cfg/ltsig_key");
  //fs_unlink("/lfs/cfg/rec_salt");
  struct fs_dirent entry;
  if(-ENOENT == fs_stat("/lfs/cfg", &entry)) {
    LOG_WRN("W /lfs/cfg doesn't exist, initializing");
    fs_mkdir("/lfs/cfg");
    if(0!=initcfg(cfg)) return -1;
    printb64("noise pk",32,cfg->noise_pk);
    printb64("ltsig pk",32,cfg->ltsig_pk);
    return 0;
  }

  if(0!=loadcfg("/lfs/cfg/noise_key", 32, cfg->noise_sk)) return -1;
  Noise_XK_dh_secret_to_public(cfg->noise_pk, cfg->noise_sk);
  //printb64("noise sk",32,cfg->noise_sk);
  printb64("noise pk",32,cfg->noise_pk);

  uint8_t noise_seed[crypto_sign_SEEDBYTES];
  if(0!=loadcfg("/lfs/cfg/ltsig_seed", crypto_sign_SEEDBYTES, noise_seed)) {
    LOG_ERR("E failed to init ltsig_seed");
    return -1;
  }
  if(0!=crypto_sign_seed_keypair(cfg->ltsig_pk, cfg->ltsig_sk, noise_seed)) {
    LOG_ERR("E failed to derive ltsig keypair");
    return -1;
  }
  sodium_memzero(noise_seed,sizeof noise_seed);
  //printb64("ltsig sk",crypto_sign_SECRETKEYBYTES,cfg->ltsig_sk);
  printb64("ltsig pk",32,cfg->ltsig_pk);
  if(0!=loadcfg("/lfs/cfg/record_salt", 32, cfg->rec_salt)) return -1;
  log_flush();
  return 0;
}

int main(void) {
  int err;
  LOG_INF("Klutshnik BLE device");

  err = bt_nus_cb_register(&nus_listener, NULL);
  if (err) {
     LOG_WRN("Failed to register NUS callback: %d", err);
     return err;
  }

  err = bt_enable(NULL);
  if (err) {
     LOG_WRN("Failed to enable bluetooth: %d", err);
     return err;
  }

  start_adv();

  char addr_s[BT_ADDR_LE_STR_LEN];
  bt_addr_le_t addr = {0};
  size_t count = 1;
  bt_id_get(&addr, &count);
  bt_addr_le_to_str(&addr, addr_s, sizeof(addr_s));
  LOG_INF("MAC address: %s", addr_s);

  //err = fs_mount(mountpoint);
  //if (err < 0 && err != -EBUSY) {
  //  printk("FAIL: mount id %" PRIuPTR " at %s: %d\n",
  //         (uintptr_t)mountpoint->storage_dev, mountpoint->mnt_point, err);

  //  err = fs_mkfs(MKFS_FS_TYPE, (uintptr_t)MKFS_DEV_ID, NULL, MKFS_FLAGS);
  //  if (err < 0) {
  //    printk("FAIL: lfs format: %d\n", err);
  //    return err;
  //  }

  //  err = fs_mount(mountpoint);
  //  if (err < 0) {
  //    printk("FAIL: mount id %" PRIuPTR " at %s: %d\n",
  //           (uintptr_t)mountpoint->storage_dev, mountpoint->mnt_point, err);
  //    return err;
  //  }
  //}
  LOG_INF("%s mount", mountpoint->mnt_point);

  struct fs_statvfs sbuf;
  err = fs_statvfs(mountpoint->mnt_point, &sbuf);
  if (err < 0) {
    LOG_ERR("FAIL: statvfs: %d", err);
    //err = fs_unmount(mountpoint);
    //printk("%s unmount: %d\n", mountpoint->mnt_point, err);
    return err;
  }
  LOG_INF("%s: bsize = %lu ; frsize = %lu ;"
          " blocks = %lu ; bfree = %lu\n",
          mountpoint->mnt_point,
          sbuf.f_bsize, sbuf.f_frsize,
          sbuf.f_blocks, sbuf.f_bfree);

  CFG cfg;
  getcfg(&cfg);

  // todo remove
  //rmdir("/lfs/data/4af18995bd5484ae3971825aee7255e7fd72a0fc00aa20b5d6732079bcd801f9");

  LOG_INF("Initialization complete");

  while (true) {
    while(cstate != CONNECTED) {
      LOG_DBG("Waiting for noise connection");
      if(-1==setup_noise_connection()) {
        LOG_ERR("failed to setup noise connection, resetting ble");
        reset_ble();
      }
    };

    while(1) {
      uint8_t *pkt;
      int ret = read(0, &pkt);
      if(ret < 0) {
        if(ret==-ETIMEDOUT) {
          k_sleep(K_MSEC(10));
          continue;
        }
        if(ret==-ENOTCONN) break;
        LOG_ERR("error reading initial request packet: %d", ret);
        //sys_reboot(SYS_REBOOT_COLD);
      }
      switch(pkt[0]) {
      case OP_CREATE: {
        if(ret!=sizeof(CreateReq)) {
          LOG_ERR("CreateReq has invalid size %d != %d.", ret, sizeof(CreateReq));
          break;
        }
        LOG_INF("create req");
        stp_dkg(&cfg, (CreateReq*) pkt);
        break;
      }
      case OP_DECRYPT: {
        if(ret!=sizeof(DecryptReq)) {
          LOG_ERR("DecryptReq has invalid size %d != %d.", ret, sizeof(DecryptReq));
          break;
        }
        LOG_INF("decrypt req");
        decrypt(&cfg, (DecryptReq*) pkt);
        break;
      }
      case OP_REFRESH: {
        if(ret!=sizeof(RefreshReq)) {
          LOG_ERR("DecryptReq has invalid size %d != %d.", ret, sizeof(RefreshReq));
          break;
        }
        LOG_INF("refresh req");
        refresh(&cfg, (RefreshReq*) pkt);
        break;
      }
      case OP_DELETE: {
        if(ret!=sizeof(DeleteReq)) {
          LOG_ERR("DeleteReq has invalid size %d != %d.", ret, sizeof(DeleteReq));
          break;
        }
        LOG_INF("delete req");
        delete(&cfg, (DeleteReq*) pkt);
        break;
      }
      case OP_UPDATE: {
        if(ret!=sizeof(UpdateReq)) {
          LOG_ERR("UpdateReq has invalid size %d != %d.", ret, sizeof(UpdateReq));
          break;
        }
        LOG_INF("update req");
        toprf_update(&cfg, (UpdateReq*) pkt);
        break;
      }
      case OP_MODAUTH: {
        if(ret!=sizeof(ModAuthReq)) {
          LOG_ERR("ModAuthReq has invalid size %d != %d.", ret, sizeof(ModAuthReq));
          break;
        }
        LOG_INF("modauth req");
        modauth(&cfg, (ModAuthReq*) pkt);
        break;
      }
      default: {
        LOG_ERR("unknown opcode: %d. resetting", pkt[0]);
        //sys_reboot(SYS_REBOOT_COLD);
      }
      }
      free(pkt);
    }
  }

  return 0;
}
