/*
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#ifdef CONFIG_KLUTSHNIK_USB_CDC

#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/uart.h>
#include <zephyr/sys/ring_buffer.h>
#include <zephyr/logging/log.h>
#include <zephyr/logging/log_ctrl.h>
#include <zephyr/sys/reboot.h>

#include "XK.h"

LOG_MODULE_REGISTER(klutshnik_uart, CONFIG_KLUTSHNIK_LOG_LEVEL);

#include "klutshnik.h"

const struct device * uart_dev = DEVICE_DT_GET(DT_NODELABEL(cdc_acm_uart1));

//struct ring_buf ringbuf;
//static bool rx_throttled;

void dtr_monitor(void) {
  uint32_t dtr = 0;
  while (1) {
    uart_line_ctrl_get(uart_dev, UART_LINE_CTRL_DTR, &dtr);
    if(dtr && kstate == DISCONNECTED) {
      LOG_INF("usb-cdc uart connected");
      //log_flush();
      kstate=CONNECTED;
    }
    else if(!dtr && kstate == CONNECTED) {
      LOG_INF("usb-cdc uart disconnected");
      //log_flush();
      kstate=DISCONNECTED;
      //inbuf_end=0;
      //inbuf_start=0;
    }
    k_sleep(K_MSEC(10));
  }
}

#define DTR_MONITOR_PRIORITY 5
#define DTR_MONITOR_STACK_SIZE 512

K_THREAD_DEFINE(dtr_monitor_tid, DTR_MONITOR_STACK_SIZE,
                dtr_monitor, NULL, NULL, NULL,
                DTR_MONITOR_PRIORITY, 0, 0);


int send_plaintext(const uint8_t *msg, const size_t len) {
  k_thread_suspend(dtr_monitor_tid);
  for(size_t i = 0;i<len;i++) {
    uart_poll_out(uart_dev, msg[i]);
    if(i%768==0) k_sleep(K_MSEC(10));
  }
  k_thread_resume(dtr_monitor_tid);
  LOG_INF("sent %dB", len);
  log_flush();
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

int is_connected(void) {
  int dtr;
  uart_line_ctrl_get(uart_dev, UART_LINE_CTRL_DTR, &dtr);
  return dtr;
}

int read_raw(const size_t size) {
  if(inbuf_end+size >= sizeof(inbuf)) return -EOVERFLOW;
  int64_t timeout = 3;

  k_thread_suspend(dtr_monitor_tid);
  for(size_t i=0;i<size;) {
    int64_t start = k_uptime_get();
    while(-1==uart_poll_in(uart_dev,&inbuf[inbuf_end])) {
      if(!is_connected()) {
        kstate=DISCONNECTED;
        k_thread_resume(dtr_monitor_tid);
        return -ENOTCONN;
      }
      int64_t startcopy=start;
      if( k_uptime_delta(&startcopy)/MSEC_PER_SEC > timeout) {
        LOG_ERR("read_raw(%d) timeout [%d,%d]", size, inbuf_start, inbuf_end);
        log_flush();
        k_thread_resume(dtr_monitor_tid);
        return -ETIMEDOUT;
      }
      k_sleep(K_MSEC(10));
    }
    inbuf_end++;
    i++;
  }
  k_thread_resume(dtr_monitor_tid);
  LOG_INF("read_raw(%d) [%d,%d]", size, inbuf_start, inbuf_end);
  //log_flush();
  return 0;
}

int read(size_t size, uint8_t **buf) {
  //if(!is_connected()) kstate=DISCONNECTED;
  //if(kstate!=CONNECTED) return -ENOTCONN;
  //LOG_DBG("read: %d", size);
  //int64_t timeout = 3;
  //int64_t start = k_uptime_get();
  size_t plen = 0;

  if(0!=read_raw(2)) return -ETIMEDOUT;

  plen = (inbuf[inbuf_start]<<8 | inbuf[inbuf_start+1]);
  LOG_INF("read(%d), plen=%d, [%d,%d]", size, plen, inbuf_start, inbuf_end);
  log_flush();
  if(plen >= sizeof(inbuf) - inbuf_start) return -EOVERFLOW;
  if(size==0) {
    size=plen-16;
  } else if(plen!=size+16) {
    LOG_ERR("E plen: %d, size+16 = %d", plen, size+16);
    return -EMSGSIZE;
  }

  if(0!=read_raw(plen)) return -ETIMEDOUT;

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

int uart_init(CFG *cfg) {
  LOG_INF("waiting until CDC device is ready");
  log_flush();
  if (!device_is_ready(uart_dev)) {
    LOG_ERR("CDC ACM device not ready");
    return -1;
  }

  LOG_INF("monitor tid: %d", dtr_monitor_tid);
  log_flush();

  uint8_t tmp[32];
  Noise_XK_dh_secret_to_public(tmp, cfg->noise_sk);
  printb64("noise pk",32,tmp);
  crypto_sign_ed25519_sk_to_pk(tmp,cfg->ltsig_sk);
  printb64("ltsig pk",32,tmp);

  return 0;
}

#endif // CONFIG_KLUTSHNIK_USB_CDC
