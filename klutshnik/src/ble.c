/*
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#ifdef CONFIG_KLUTSHNIK_BLE

#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/services/nus.h>
#include <zephyr/fs/fs.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>

#include <stdlib.h>
#include "XK.h"

#include "klutshnik.h"

LOG_MODULE_REGISTER(klutshnik_ble, CONFIG_KLUTSHNIK_LOG_LEVEL);

#define MTU 20
#define DEVICE_NAME		CONFIG_BT_DEVICE_NAME
#define DEVICE_NAME_LEN	(sizeof(DEVICE_NAME) - 1)

static struct bt_conn *bt_c=NULL;

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

static void received(struct bt_conn *conn, const void *data, uint16_t len, void *ctx) {
	ARG_UNUSED(conn);
	ARG_UNUSED(ctx);

   if(kstate!=CONNECTED) {
     LOG_ERR("received %d bytes, but we are in disconnected state", len);
     return;
   }
   if(len + inbuf_end<sizeof(inbuf)) {
     //LOG_INF("received: memcpy(%p, %p, %d)", (void*) (inbuf+inbuf_end), (void*) data, len);
     memcpy(inbuf+inbuf_end, data, len);
     inbuf_end+=len;
   } else{
     LOG_ERR("inbuf full, dropping %d bytes", len);
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

   err = bt_le_adv_start(/*BT_LE_ADV_CONN_FAST_1*/BT_LE_ADV_PARAM((BT_LE_ADV_OPT_CONN |
                                                                   BT_LE_ADV_OPT_USE_IDENTITY), /* Connectable advertising and use identity address */
                                                                  BT_GAP_ADV_FAST_INT_MIN_1, /* Min Advertising Interval 30 ms */
                                                                  BT_GAP_ADV_FAST_INT_MAX_1, /* Max Advertising Interval 60 ms */
                                                                  NULL), /* Set to NULL for undirected advertising */
                         ad, ARRAY_SIZE(ad), sd, ARRAY_SIZE(sd));
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

int send_plaintext(const uint8_t *msg, const size_t len) {
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

int send(const uint8_t *msg, const size_t msg_len) {
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

  int err= send_plaintext(cipher_msg, cipher_msg_len);
  if (cipher_msg_len > 0) free(cipher_msg);
  if(err == -ENOTCONN) {
    Noise_XK_session_free(session);
    session=NULL;
    Noise_XK_device_free(dev);
    dev=NULL;
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

int send_pkt(const uint8_t *msg, const size_t msg_len) {
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

  return plain_msg_len;
}

void reset_ble(void) {
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

int ble_disconnect(void) {
  if(bt_c==NULL) return -ENOTCONN;
  return bt_conn_disconnect(bt_c, BT_HCI_ERR_REMOTE_USER_TERM_CONN);
}

int ble_init(CFG *cfg) {
  int err = bt_enable(NULL);
  if (err) {
     LOG_WRN("Failed to enable bluetooth: %d", err);
     return err;
  }

  uint8_t tmp[32];
  Noise_XK_dh_secret_to_public(tmp, cfg->noise_sk);
  printb64("noise pk",32,tmp);
  crypto_sign_ed25519_sk_to_pk(tmp,cfg->ltsig_sk);
  printb64("ltsig pk",32,tmp);

  err = bt_nus_cb_register(&nus_listener, NULL);
  if (err) {
     LOG_WRN("Failed to register NUS callback: %d", err);
     return err;
  }

  start_adv();

  char addr_s[BT_ADDR_LE_STR_LEN];

  struct bt_le_oob oob;
  err = bt_le_oob_get_local(BT_ID_DEFAULT, &oob);
  if (err) {
    LOG_ERR("Failed to get OOB data (err %d)\n", err);
    return err;
  }
  bt_addr_le_to_str(&oob.addr, addr_s, sizeof(addr_s));
  //bt_addr_le_t addr = {0};
  //size_t count = 1;
  //bt_id_get(&addr, &count);
  //bt_addr_le_to_str(&addr, addr_s, sizeof(addr_s));
  LOG_INF("MAC address: %s", addr_s);

  kstate = DISCONNECTED;
  return 0;
}

#endif // CONFIG_KLUTSHNIK_BLE
