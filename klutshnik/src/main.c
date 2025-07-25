/*
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
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
#include <zephyr/drivers/uart.h>

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

#define UART_DEVICE_NODE DT_NODELABEL(usb_serial)

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

#if DT_NODE_EXISTS(UART_DEVICE_NODE)
static const struct device *const uart_dev = DEVICE_DT_GET(UART_DEVICE_NODE);

//#define UART_MSG_SIZE 37
///* queue to store up to 10 messages (aligned to 4-byte boundary) */
//K_MSGQ_DEFINE(uart_msgq, UART_MSG_SIZE, 1, 4);
//
///* receive buffer used in UART ISR callback */
//static char uart_rx_buf[UART_MSG_SIZE];
//static int uart_rx_buf_pos;
#endif

typedef enum {
  DISCONNECTED,
  CONNECTED,
  //SECURE
} KlutshnikState;

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

typedef struct {
  uint8_t keyid[32];
  uint8_t ltsig[32];
  uint8_t noise[32];
} __attribute__((__packed__)) AuthKeys;

typedef struct {
  uint8_t noise_sk[32];
  uint8_t ltsig_sk[crypto_sign_SECRETKEYBYTES];
  uint8_t rec_salt[32];
} CFG;

static uint8_t inbuf[1024*32];
static int inbuf_end=0;
static int inbuf_start=0;
static KlutshnikState kstate=DISCONNECTED;
static struct bt_conn *bt_c=NULL;
static Noise_XK_session_t *session=NULL;
static Noise_XK_device_t *dev=NULL;
static uint64_t ref_time;

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

uint64_t ztime(void) {
  uint64_t now = k_uptime_seconds();
  return htonll(now + ref_time);
}

static void received(struct bt_conn *conn, const void *data, uint16_t len, void *ctx) {
	ARG_UNUSED(conn);
	ARG_UNUSED(ctx);

   if(kstate!=CONNECTED) {
     LOG_ERR("received %d bytes, but we are in disconnected state", len);
     return;
   }
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
    kstate = CONNECTED;
    bt_c = conn;
  }
}

static void disconnected(struct bt_conn *conn, uint8_t reason) {
  const bt_addr_le_t *addr = bt_conn_get_dst (conn);
  LOG_INF("Disconnected from %02x-%02x-%02x-%02x-%02x-%02x (reason 0x%02x)",
          addr->a.val[0],addr->a.val[1],addr->a.val[2],addr->a.val[3],addr->a.val[4],addr->a.val[5], reason);
  kstate = DISCONNECTED;
  bt_c = NULL;
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
  //LOG_DBG("nus_send: %d", len);
  for(size_t ptr = 0;ptr<len;ptr+=20) {
    int err=0;
    const int psize=((len-ptr)>20)?20:(len-ptr);
    do {
      err = bt_nus_send(bt_c, &msg[ptr], psize);
    } while (err == -EAGAIN);
    if(err<0) return err;
  }
  //LOG_DBG("nus_send: done", len);
  return 0;
}

static int send(const uint8_t *msg, const size_t msg_len) {
  //LOG_DBG("send: %d", msg_len);
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

  //LOG_DBG("sent", msg_len);
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
  //LOG_DBG("read: %d", size);
  int64_t timeout = 3;
  int64_t start = k_uptime_get();
  size_t plen = 0;
  while(1) {
    if(kstate!=CONNECTED) return -ENOTCONN;
    if (plen == 0 && inbuf_end-inbuf_start>2) {
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

  //LOG_DBG("read: done");

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

  inbuf_start += plen+2;
  if(inbuf_start == inbuf_end) {
    inbuf_start=0;
    inbuf_end=0;
  } else if(inbuf_start > inbuf_end) return -EINVAL;

  //LOG_DBG("decrypted");
  return plain_msg_len;
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

    char fname[MAX_PATH_LEN+1];
    snprintf(fname, sizeof(fname), "%s/%s", path, dirent.name);

    if (dirent.type == FS_DIR_ENTRY_DIR) {
      LOG_WRN("W is a dir: %s", fname);
      rmdir(fname);
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

static int load_noisekeys(const CFG *cfg, Noise_XK_device_t *dev) {
  const char fname[]="/lfs/cfg/authorized_clients";
  struct fs_file_t file;
  fs_file_t_init(&file);
  int rc = fs_open(&file, fname, FS_O_READ);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", fname, rc);
    return rc;
  }

  int count = 0;
  while(1) {
    uint8_t k[32];
    rc = fs_read(&file, k, 32);
    if (rc < 0) {
      LOG_ERR("FAIL: read %s: %d", fname, rc);
      goto out;
    }
    if(rc==0) {
      rc = count;
      goto out;
    }
    if(rc!=32) {
      LOG_ERR("FAIL: short read only %dB instead of 32B", rc);
      goto out;
    }
    if (!Noise_XK_device_add_peer(dev, (uint8_t*) "klutshnik client", k)) {
      LOG_ERR("Failed to add client key to noise device");
      rc = -1;
      goto out;
    }
    count++;
  }

out:
  int ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", fname, ret);
    return ret;
  }

  return rc;
}

static int setup_noise_connection(CFG *cfg) {
  LOG_INF("trying to establish connection");
  const uint8_t dst[]="klutshnik ble tle";
  const uint8_t noise_name[]="klutshnik server 1";
  const uint8_t srlz_key[AEAD_KEY_SIZE] = {0};
  dev = Noise_XK_device_create(sizeof(dst)-1, dst, noise_name, srlz_key, cfg->noise_sk);
  load_noisekeys(cfg,dev);
  session = Noise_XK_session_create_responder(dev);
  if(!session) {
     LOG_ERR("Failed to create noise session");
     Noise_XK_device_free(dev);
     return -1;
  }

  while(kstate!=CONNECTED) {
    // todo refactor this
    //if(uc=='r') {
    //  LOG_INF("resetting /data");
    //  log_flush();
    //  rmdir("/lfs/data");
    //  fs_mkdir("/lfs/data");
    //  uc=0;
    //}
    k_sleep(K_MSEC(10));
  };
  while(kstate==CONNECTED && inbuf_end!=48) k_sleep(K_MSEC(10));
  if(kstate!=CONNECTED) {
    Noise_XK_session_free(session);
    Noise_XK_device_free(dev);
    return ENOTCONN;
  }

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
    LOG_ERR("error sending handshake: %d", err);
    log_flush();
    k_sleep(K_MSEC(50));
    sys_reboot(SYS_REBOOT_COLD);
  }

  while(kstate==CONNECTED && inbuf_end!=64) k_sleep(K_MSEC(10));
  if(kstate!=CONNECTED) return ENOTCONN;
  inbuf_end=0;

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
  kstate=DISCONNECTED;
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

static int getperm(const CFG *cfg,
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

  if(0!=auth(cfg, OP_UPDATE, (uint8_t *) req->pk, sizeof(UpdateReq), (uint8_t*) req)) {
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

typedef struct {
  size_t len;
  AuthKeys *auth_keys;
} Keyloader_CB_Arg;

static int load_authkeys(Keyloader_CB_Arg *cb_arg) {
  struct fs_dirent dirent;
  const char fname[]="/lfs/cfg/authorized_keys";
  int rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    if(rc == -ENOENT) return 0;
    LOG_ERR("FAIL: stat %s: %d", fname, rc);
    return rc;
  } else {
    if(dirent.type != FS_DIR_ENTRY_FILE) {
      LOG_ERR("E error %s is not a file", fname);
      return -EISDIR;
    }
  }
  if(dirent.size == 0) return -ENODATA;
  if(dirent.size % 64 != 0) return -EINVAL;
  cb_arg->len = dirent.size / 64;
  cb_arg->auth_keys = k_malloc(sizeof(AuthKeys) * cb_arg->len);

  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, fname, FS_O_READ);
  if (rc < 0) {
    LOG_ERR("FAIL: open %s: %d", fname, rc);
    return rc;
  }

  for(int i=0;i<cb_arg->len;i++) {
    rc = fs_read(&file, cb_arg->auth_keys[i].ltsig, 64);
    if (rc < 0) {
      LOG_ERR("FAIL: read %s: %d", fname, rc);
      goto out;
    }
    if(rc!=64) {
      LOG_ERR("FAIL: short read only %dB instead of 64B", rc);
      return -EINVAL;
    }
    crypto_generichash(cb_arg->auth_keys[i].keyid,32,cb_arg->auth_keys[i].ltsig,crypto_sign_PUBLICKEYBYTES,NULL,0);
  }

out:
  int ret = fs_close(&file);
  if (ret < 0) {
    LOG_ERR("FAIL: close %s: %d", fname, ret);
    return ret;
  }

  return (rc < 0 ? rc : 0);
}

int keyloader_cb(const uint8_t id[crypto_generichash_BYTES], void *arg, uint8_t sigpk[crypto_sign_PUBLICKEYBYTES], uint8_t noise_pk[crypto_scalarmult_BYTES]) {
  Keyloader_CB_Arg *args = (Keyloader_CB_Arg *) arg;
  for(unsigned i=0;i<args->len;i++) {
    if(memcmp(args->auth_keys[i].keyid, id, crypto_generichash_BYTES) == 0) {
      memcpy(sigpk, args->auth_keys[i].ltsig, crypto_sign_PUBLICKEYBYTES);
      memcpy(noise_pk, args->auth_keys[i].noise, crypto_scalarmult_BYTES);
      return 0;
    }
  }
  uint8_t hex[crypto_generichash_BYTES*2+1];
  hex[sizeof(hex)-1]=0;
  bin2hex(id,crypto_generichash_BYTES,hex,sizeof(hex));
  LOG_ERR("E stp-dkg: no auth key found for keyid: %s", hex);
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
  Keyloader_CB_Arg keyloader_args;
  if(0!=load_authkeys(&keyloader_args)) {
    LOG_ERR("failed to load authorized_keys. aborting.");
    return -1;
  }

  if(0!=stp_dkg_peer_set_bufs(&ctx, &peerids,
                              &keyloader_cb, &keyloader_args,
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

static int decrypt(const CFG *cfg, const DecryptReq *req) {
  int ret;
  if(0!=auth(cfg, OP_DECRYPT, (uint8_t*) req->pk, sizeof(DecryptReq), (uint8_t*) req)) {
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
  if(0!=auth(cfg, OP_MODAUTH, (uint8_t*) pk, sizeof(ModAuthReq), (uint8_t*) req)) {
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
  int ret;
  if(0!=auth(cfg, OP_REFRESH, (uint8_t*) req->pk, sizeof(RefreshReq), (uint8_t*) req)) {
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
  if(0!=auth(cfg, OP_DELETE, (uint8_t*) req->pk, sizeof(DeleteReq), (uint8_t*) req)) {
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

static int save(const char *path, const size_t key_len, uint8_t *key, const int open_flags) {
  struct fs_file_t file;
  int rc, ret;
  fs_file_t_init(&file);
  rc = fs_open(&file, path, FS_O_CREATE | FS_O_WRITE | open_flags);
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

  return save(path,key_len,key,0);
}

static int initcfg(CFG *cfg) {
  int rc;
  rc = initkey("/lfs/cfg/noise_key", 32, cfg->noise_sk);
  if(rc!=0) {
    LOG_ERR("E failed to init noise_sk");
    return rc;
  }

  uint8_t ltsig_seed[crypto_sign_SEEDBYTES];
  rc = initkey("/lfs/cfg/ltsig_seed", crypto_sign_SEEDBYTES, ltsig_seed);
  if(rc!=0) {
    LOG_ERR("E failed to init ltsig_seed");
    return rc;
  }
  uint8_t dummy[crypto_sign_PUBLICKEYBYTES];
  if(0!=crypto_sign_seed_keypair(dummy, cfg->ltsig_sk, ltsig_seed)) {
    LOG_ERR("E failed to derive ltsig keypair");
    return -1;
  }
  sodium_memzero(ltsig_seed,sizeof ltsig_seed);

  uint8_t authkey_pk[64];
  crypto_sign_ed25519_sk_to_pk(authkey_pk, cfg->ltsig_sk);
  Noise_XK_dh_secret_to_public(authkey_pk+32, cfg->noise_sk);
  rc = save("/lfs/cfg/authorized_keys", 64, authkey_pk, FS_O_APPEND);
  if(0!=rc) {
    LOG_ERR("failed to save authorized keys of device: %d. aborting.", rc);
    return rc;
  }

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

//#if DT_NODE_EXISTS(UART_DEVICE_NODE)
//void serial_cb(const struct device *dev, void *cfg_p) {
//	uint8_t c;
//	if (!uart_irq_update(uart_dev)) {
//		return;
//	}
//
//	if (!uart_irq_rx_ready(uart_dev)) {
//		return;
//	}
//
//   CFG *cfg = cfg_p;
//	/* read until FIFO empty */
//   const uint8_t preamble[]="KLUTSHNIK-DEVICE-INIT";
//   static int p_idx=0;
//   static int stage=0;
//	while (uart_fifo_read(uart_dev, &c, 1) == 1) {
//     if(stage==0) {
//       if(p_idx==sizeof(preamble)) stage==1;
//       else if(c==preamble[p_idx]) p_idx++;
//       else if(p_idx>0) p_idx=0;
//       continue;
//     }
//     //if(c=='r') uc = 'r';
//     //if(uc=='I' && c=='i') {
//     //  for(int i=0;i<64;i++) {
//     //    if(uart_fifo_read(uart_dev, &cfg->auth_keys[0].ltsig[i], 1) != 1) {
//     //      LOG_ERR("failed to read auth_key from uart, at pos: %d", i);
//     //      return;
//     //    }
//     //  }
//     //  uc='i';
//     //}
//
//     //if(c=='k') uc = 'k'; read 32 bytes, put them into queue
//     //if ((c == '\n' || c == '\r') && uart_rx_buf_pos > 0) {
//     //  /* terminate string */
//     //  uart_rx_buf[uart_rx_buf_pos] = '\0';
//
//     //  /* if queue is full, message is silently dropped */
//     //  k_msgq_put(&uart_msgq, &uart_rx_buf, K_NO_WAIT);
//
//     //  /* reset the buffer (it was copied to the msgq) */
//     //  uart_rx_buf_pos = 0;
//     //} else if (uart_rx_buf_pos < (sizeof(uart_rx_buf) - 1)) {
//     //  uart_rx_buf[uart_rx_buf_pos++] = c;
//     //}
//	}
//}
//#endif

static int getcfg(CFG *cfg) {
  if(0!=loadcfg("/lfs/cfg/noise_key", 32, cfg->noise_sk)) return -1;

  uint8_t noise_seed[crypto_sign_SEEDBYTES];
  if(0!=loadcfg("/lfs/cfg/ltsig_seed", crypto_sign_SEEDBYTES, noise_seed)) {
    LOG_ERR("E failed to init ltsig_seed");
    return -1;
  }
  uint8_t dummy[crypto_sign_PUBLICKEYBYTES];
  if(0!=crypto_sign_seed_keypair(dummy, cfg->ltsig_sk, noise_seed)) {
    LOG_ERR("E failed to derive ltsig keypair");
    return -1;
  }
  sodium_memzero(noise_seed,sizeof noise_seed);
  if(0!=loadcfg("/lfs/cfg/record_salt", 32, cfg->rec_salt)) return -1;

  return 0;
}

//static int start_uart_recv(CFG *cfg) {
//#if DT_NODE_EXISTS(UART_DEVICE_NODE)
//  if (!device_is_ready(uart_dev)) {
//    LOG_ERR("UART device not found!");
//    return -1;
//  }
//  LOG_INF("UART device found!");
//  err = uart_irq_callback_user_data_set(uart_dev, serial_cb, cfg);
//  if (err < 0) {
//    if (err == -ENOTSUP) {
//      LOG_ERR("Interrupt-driven UART API support not enabled");
//    } else if (err == -ENOSYS) {
//      LOG_ERR("UART device does not support interrupt-driven API");
//    } else {
//      LOG_ERR("Error setting UART callback: %d", err);
//    }
//  } else {
//    uart_irq_rx_enable(uart_dev);
//  }
//#endif
//}

static int uart_recv_cfg(CFG *cfg) {
   printk("no configuration found. waiting for initialization");

   const uint8_t preamble[]="KLUTSHNIK-DEVICE-INIT";
   int p_idx=0, ret;
   char c;

   // read preamble
	while(1) {
     ret = uart_poll_in(uart_dev, &c);
     if(ret==-1) {
       k_sleep(K_MSEC(10));
       continue;
     }
     if(ret<0) {
       LOG_ERR("uart poll returned error: %d", ret);
       log_flush();
       sys_reboot(SYS_REBOOT_COLD);
     }
     if(c==preamble[p_idx]) p_idx++;
     else if(p_idx>0) {
       p_idx=0;
       continue;
     }
     if(p_idx==sizeof(preamble)-1) break;
   }

   p_idx=0;
   size_t pkt_len = 0;

   // read total length
	while(p_idx<2) {
     ret = uart_poll_in(uart_dev, &c);
     if(ret==-1) {
       k_sleep(K_MSEC(10));
       continue;
     }
     if(ret<0) {
       LOG_ERR("uart poll returned error: %d", ret);
       log_flush();
       sys_reboot(SYS_REBOOT_COLD);
     }
     pkt_len = (pkt_len << 8) | c;
     p_idx++;
   }
   //LOG_DBG("init pkt size: %d", pkt_len);
   if(pkt_len<64+1+64*2) {
     LOG_ERR("cfg packet is too small: %d", pkt_len);
   }

   uint8_t pkt[pkt_len];
   p_idx=0;
	while(p_idx<pkt_len) {
     ret = uart_poll_in(uart_dev, &c);
     if(ret==-1) {
       k_sleep(K_MSEC(10));
       continue;
     }
     if(ret<0) {
       LOG_ERR("uart poll returned error: %d", ret);
       log_flush();
       sys_reboot(SYS_REBOOT_COLD);
     }
     pkt[p_idx++] = c;
   }
   int auth_key_len = pkt[64];
   LOG_DBG("read init pkt. contains %d authorized_keys", auth_key_len);

   if(auth_key_len*64+65!=pkt_len) {
     LOG_ERR("invalid number of authorized_keys: %d, does not correspond to packet size of %d", pkt[64], pkt_len);
     log_flush();
     sys_reboot(SYS_REBOOT_COLD);
   }

   LOG_DBG("Saving config");
   fs_mkdir("/lfs/cfg");
   ret=save("/lfs/cfg/authorized_clients", 32, pkt+32, 0);
   if(0!=ret) {
     LOG_ERR("failed to save authorized client key of initializer: %d. aborting.", ret);
     rmdir("/lfs/cfg");
     log_flush();
     sys_reboot(SYS_REBOOT_COLD);
   }

   uint8_t *key = pkt+65;
   for(int i=0;i<auth_key_len;i++,key+=64) {
     if(memcmp(pkt,key,64)==0) continue;
     LOG_HEXDUMP_INF(key, 64, "saving authorized_key");
     ret = save("/lfs/cfg/authorized_keys", 64, key, FS_O_APPEND);
     if(0!=ret) {
       LOG_ERR("failed to save authorized client key of initializer: %d. aborting.", ret);
       rmdir("/lfs/cfg");
       log_flush();
       sys_reboot(SYS_REBOOT_COLD);
     }
   }
   LOG_DBG("Saved cfg");

   return 0;
}

static int boot(CFG *cfg) {
  int err;
  LOG_INF("Klutshnik device initializing");

  LOG_INF("%s mount", mountpoint->mnt_point);
  struct fs_statvfs sbuf;
  err = fs_statvfs(mountpoint->mnt_point, &sbuf);
  if (err < 0) {
    LOG_ERR("FAIL: statvfs: %d", err);
    return err;
  }
  LOG_INF("%s: bsize = %lu ; frsize = %lu ;"
          " blocks = %lu ; bfree = %lu",
          mountpoint->mnt_point,
          sbuf.f_bsize, sbuf.f_frsize,
          sbuf.f_blocks, sbuf.f_bfree);

  struct fs_dirent entry;
  int rc = fs_stat("/lfs/cfg", &entry);
  if(-ENOENT == rc) {
    LOG_WRN("W /lfs/cfg doesn't exist, initializing");

    if(0!=uart_recv_cfg(cfg)) {
      LOG_ERR("failed to receive config via UART. halting.");
      log_flush();
      sys_reboot(SYS_REBOOT_COLD);
    }

    if(0!=initcfg(cfg)) {
      LOG_ERR("failed to initialize config. halting.");
      log_flush();
      sys_reboot(SYS_REBOOT_COLD);
    }
  } else if(rc==0) {
    if(getcfg(cfg)<0) {
      LOG_ERR("failed to load config. please fix configuration. halting.");
      log_flush();
      sys_reboot(SYS_REBOOT_COLD);
    }
  } else {
    LOG_ERR("failed to stat /lfs/cfg: %d. halting.", rc);
    log_flush();
    sys_reboot(SYS_REBOOT_COLD);
  }

  uint8_t tmp[32];
  Noise_XK_dh_secret_to_public(tmp, cfg->noise_sk);
  printb64("noise pk",32,tmp);
  crypto_sign_ed25519_sk_to_pk(tmp,cfg->ltsig_sk);
  printb64("ltsig pk",32,tmp);

  err = bt_enable(NULL);
  if (err) {
     LOG_WRN("Failed to enable bluetooth: %d", err);
     return err;
  }

  char addr_s[BT_ADDR_LE_STR_LEN];
  bt_addr_le_t addr = {0};
  size_t count = 1;
  bt_id_get(&addr, &count);
  bt_addr_le_to_str(&addr, addr_s, sizeof(addr_s));
  LOG_INF("MAC address: %s", addr_s);

  err = bt_nus_cb_register(&nus_listener, NULL);
  if (err) {
     LOG_WRN("Failed to register NUS callback: %d", err);
     return err;
  }

  start_adv();

  kstate = DISCONNECTED;

  LOG_INF("Initialization complete");
  return 0;
}

int main(void) {
  CFG cfg;
  boot(&cfg);

  while (true) {
    while(kstate != CONNECTED) {
      LOG_DBG("Waiting for noise connection");
      if(-1==setup_noise_connection(&cfg)) {
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
