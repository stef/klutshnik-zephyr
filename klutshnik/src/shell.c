/*
 * SPDX-FileCopyrightText: 2025, Marsiske Stefan
 * SPDX-License-Identifier: LGPL-3.0-or-later
 */

#include <zephyr/fs/fs.h>
#include <zephyr/shell/shell.h>
#include <zephyr/sys/base64.h>
#ifdef CONFIG_KLUTSHNIK_BLE
#include <zephyr/bluetooth/bluetooth.h>
#endif

#include <sodium.h>
#include "klutshnik.h"
#include "XK.h"

static int getcfg_cmd_handler(const struct shell *sh, size_t argc, char **argv, void *data) {
  int cfgtype = (int)data;

  switch(cfgtype) {
  case 1: {
    uint8_t ltsig_pk[crypto_sign_PUBLICKEYBYTES];
    uint8_t ltsig_seed[crypto_sign_SEEDBYTES];
    if(0!=load("/lfs/cfg/ltsig_seed", crypto_sign_SEEDBYTES, ltsig_seed)) {
      shell_error(sh, "E failed to init ltsig_seed");
      return -1;
    }
    uint8_t ltsig_sk[crypto_sign_SECRETKEYBYTES];
    if(0!=crypto_sign_seed_keypair(ltsig_pk, ltsig_sk, ltsig_seed)) {
      shell_error(sh, "E failed to derive ltsig keypair");
      return -1;
    }
    sodium_memzero(ltsig_sk,sizeof ltsig_sk);
    sodium_memzero(ltsig_seed,sizeof ltsig_seed);
    uint8_t b64[45];
    size_t olen;
    base64_encode(b64,sizeof b64,&olen,ltsig_pk,sizeof ltsig_pk);
    shell_print(sh, "ltsig pk: %s", b64);
    break;
  }
  case 2: {
    uint8_t noise_sk[32];
    if(0!=load("/lfs/cfg/noise_key", 32, noise_sk)) {
      shell_error(sh, "could not load noise key");
      return -1;
    }
    uint8_t noise_pk[32];
    Noise_XK_dh_secret_to_public(noise_pk, noise_sk);
    uint8_t b64[45];
    size_t olen;
    base64_encode(b64,sizeof b64,&olen,noise_pk,sizeof noise_pk);
    shell_print(sh, "noise pk: %s", b64);
    break;
  }
  case 3: {
#ifdef CONFIG_KLUTSHNIK_BLE
    struct bt_le_oob oob;
    int err = bt_le_oob_get_local(BT_ID_DEFAULT, &oob);
    if (err) {
      shell_error(sh, "Failed to get OOB data (err %d)\n", err);
      return err;
    }
    char addr_s[BT_ADDR_LE_STR_LEN];

    bt_addr_le_to_str(&oob.addr, addr_s, sizeof(addr_s));
    shell_print(sh, "MAC address: %s", addr_s);
#else
    shell_warn(sh, "No MAC, this klutshnik device doesn't do BLE");
#endif // CONFIG_KLUTSHNIK_BLE
    break;
  }
  default: {
    shell_error(sh, "unknown param: %d", cfgtype);
    return -1;
  }
  }

  return 0;
}

SHELL_SUBCMD_DICT_SET_CREATE(sub_getcfg, getcfg_cmd_handler,
    (ltsigpk, 1, "ltsig"), (noisepk, 2, "noise"), (mac, 3, "mac")
);
SHELL_CMD_REGISTER(getcfg, &sub_getcfg, "get public klutshnik config params", NULL);

static int cmd_init_ltsig(const struct shell *sh, size_t argc, char **argv) {
  if(argc!=2) {
    shell_error(sh, "Error: must provide exactly one base64 encoded client ltsig pubkey as parameter");
    return -1;
  }
  const size_t slen = strlen(argv[1]);
  if(slen!=44) {
    shell_error(sh, "Error: must provide exactly one 44 byte long base64 encoded client ltsig pubkey as parameter");
    return -1;
  }
  uint8_t ltsigpk[32];
  size_t olen;
  int err = base64_decode (ltsigpk, sizeof ltsigpk, &olen, argv[1], slen);
  if(err!=0) {
    shell_error(sh, "Error: failed to decode base64 encoded ltsig pubkey: %d", err);
    return -1;
  }
  if(olen!=sizeof ltsigpk) {
    shell_error(sh, "Error: decoded ltsigpk is too short, only %d, instead of expected %d", olen, sizeof ltsigpk);
    return -1;
  }
  fs_mkdir("/lfs/cfg");
  err=save("/lfs/cfg/owner_pk", sizeof ltsigpk, ltsigpk, 0);
  if(0!=err) {
    shell_error(sh, "failed to save authorized client key of initializng client: %d. aborting.", err);
    return -1;
  }
  return 0;
}

static int cmd_init_noise(const struct shell *sh, size_t argc, char **argv) {
  if(argc!=2) {
    shell_error(sh, "Error: must provide exactly one base64 encoded client noise pubkey as parameter");
    return -1;
  }
  const size_t slen = strlen(argv[1]);
  if(slen!=44) {
    shell_error(sh, "Error: must provide exactly one 44 byte long base64 encoded client noise pubkey as parameter");
    return -1;
  }
  uint8_t noisepk[32];
  size_t olen;
  int err = base64_decode (noisepk, sizeof noisepk, &olen, argv[1], slen);
  if(err!=0) {
    shell_error(sh, "Error: failed to decode base64 encoded noise pubkey: %d", err);
    return -1;
  }
  if(olen!=sizeof noisepk) {
    shell_error(sh, "Error: decoded noisepk is too short, only %d, instead of expected %d", olen, sizeof noisepk);
    return -1;
  }
  fs_mkdir("/lfs/cfg");
  err=save("/lfs/cfg/authorized_clients", sizeof noisepk, noisepk, 0);
  if(0!=err) {
    shell_error(sh, "failed to save authorized client noise key of initialing client: %d. aborting.", err);
    return -1;
  }
  return 0;
}

static int cmd_init_check(const struct shell *sh, size_t argc, char **argv) {
  uint8_t res=init_is_incomplete();

  if(res==0) {
    shell_print(sh, "configuration is complete");
    return 0;
  }

  for(int i=0;i<3;i++) {
    int rc = (res >> (i*2)) & 3;
    switch(rc) {
    case 1: {
      shell_error(sh, "FAIL: stat %s", init_files[i].path);
      break;
    }
    case 2: {
      shell_error(sh, "E error %s is not a file", init_files[i].path);
      break;
    }
    case 3: {
      shell_error(sh, "Error: %s is invalid size", init_files[i].path);
      break;
    }
    }
  }

  return -1;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_init,
                               SHELL_CMD_ARG(ltsig, NULL, "Set owner ltsig pubkey.", cmd_init_ltsig, 2, 0),
                               SHELL_CMD_ARG(noise, NULL, "Set owner noise pubkey.", cmd_init_noise, 2, 0),
                               SHELL_CMD(check, NULL, "Check if config is complete.", cmd_init_check),
                               SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(init, &sub_init, "initialize klutshnik device", NULL);


static int cmd_authkey_add(const struct shell *sh, size_t argc, char **argv) {
  if(argc!=2) {
    shell_error(sh, "Error: must provide exactly one base64 encoded authkey line as parameter");
    return -1;
  }
  const size_t slen = strlen(argv[1]);
  if(slen!=88) {
    shell_error(sh, "Error: authkey must be 88 bytes base64 encoded data, this one is %d", slen);
    return -1;
  }
  uint8_t authkey[64];
  size_t olen;
  int err = base64_decode (authkey, sizeof authkey, &olen, argv[1], slen);
  if(err!=0) {
    shell_error(sh, "Error: failed to decode base64 encoded authkey: %d", err);
    return -1;
  }
  if(olen!=sizeof authkey) {
    shell_error(sh, "Error: decoded authkey is too short, only %d, instead of expected %d", olen, sizeof authkey);
    return -1;
  }
  err = save("/lfs/cfg/authorized_keys", sizeof authkey, authkey, FS_O_APPEND);
  if(0!=err) {
    shell_error(sh, "failed to save authorized client key: %d. aborting.", err);
    return -1;
  }
  return 0;
}

static int cmd_authkey_del(const struct shell *sh, size_t argc, char **argv) {
  int ret = fs_unlink("/lfs/cfg/authorized_keys");
  if(ret<0) {
    shell_error(sh, "ERROR unlinking: authorized_keys");
  }
  return 0;
}

static int cmd_authkey_get(const struct shell *sh, size_t argc, char **argv) {
  struct fs_dirent dirent;
  const char fname[]="/lfs/cfg/authorized_keys";
  int rc = fs_stat(fname, &dirent);
  if (rc < 0) {
    if(rc == -ENOENT) return 0;
    shell_error(sh, "FAIL: stat %s: %d", fname, rc);
    return rc;
  } else {
    if(dirent.type != FS_DIR_ENTRY_FILE) {
      shell_error(sh, "E error %s is not a file", fname);
      return -EISDIR;
    }
  }
  if(dirent.size == 0) {
    shell_error(sh, "Error: authorized_keys is empty");
    return -ENODATA;
  }
  if(dirent.size % 64 != 0) {
    shell_error(sh, "Error: authorized_keys has an invalid length (not 0 mod 64)");
    return -EINVAL;
  }

  struct fs_file_t file;
  fs_file_t_init(&file);
  rc = fs_open(&file, fname, FS_O_READ);
  if (rc < 0) {
    shell_error(sh, "FAIL: open %s: %d", fname, rc);
    return rc;
  }

  uint8_t authkey[64];
  uint8_t authkey_b64[89];
  size_t olen;
  for(int i=0;i<dirent.size / 64;i++) {
    rc = fs_read(&file, authkey, 64);
    if (rc < 0) {
      shell_error(sh, "FAIL: read %s: %d", fname, rc);
      goto out;
    }
    if(rc!=64) {
      shell_error(sh, "FAIL: short read only %dB instead of 64B", rc);
      return -EINVAL;
    }
    base64_encode(authkey_b64,sizeof authkey_b64,&olen,authkey,sizeof authkey);
    shell_print(sh, "%s",authkey_b64);
  }

 out:
  int ret = fs_close(&file);
  if (ret < 0) {
    shell_error(sh, "FAIL: close %s: %d", fname, ret);
    return ret;
  }
  return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(sub_authkey,
                               SHELL_CMD_ARG(add, NULL, "Add an authorized_keys item.", cmd_authkey_add, 2, 0),
                               SHELL_CMD(get, NULL, "Get contents of authorized_keys.", cmd_authkey_get),
                               SHELL_CMD(del, NULL, "Delete authorized_keys file.", cmd_authkey_del),
                               SHELL_SUBCMD_SET_END
);
SHELL_CMD_REGISTER(authkey, &sub_authkey, "manage klutshnik authorized_keys", NULL);
