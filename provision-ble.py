#!/usr/bin/env python3

# SPDX-FileCopyrightText: 2025, Marsiske Stefan
# SPDX-License-Identifier: GPL-3.0-or-later

import serial, binascii, sys, tomlkit, os, struct, pyudev
from tempfile import NamedTemporaryFile
from esptool.cmds import detect_chip
from pysodium import crypto_generichash, randombytes
from pyoprf import noisexk

debug=False

def get_serial(port):
    context = pyudev.Context()
    for device in context.list_devices(subsystem='tty'):
        if device.device_node == port:
            return device.get('ID_SERIAL_SHORT')

def write_cfg(cfg, cfg_file, mac, spk, npk, noise_sk, uart):
   table = None
   # check if there is already a record with this mac
   if uart is None:
      name = f"ble_{mac.replace(':','')}"
   else:
      name = f"usb-cdc0"
   for k, server in cfg.get('servers',{}).items():
      if k == name:
         print(f'warning: there is already a server configured with the name "{name}", will overwrite values in there', file=sys.stderr)
         table = server
      elif uart is None and server.get('bleaddr') == mac:
         print(f'warning: this config already has a server configured with the name: "{k}"\n'
               f'you should merge this entry with the new entry called "{name}"', file=sys.stderr)
   if table is None:
      table = tomlkit.table(False)
      cfg.get('servers').append(name, table)

   if mac is not None:
      table.update({'bleaddr': mac})
   elif uart is not None:
      table.update({'usb_serial': uart})

   table.update({'ltsigkey': binascii.b2a_base64(spk).decode('utf8').strip(),
                 'device_pk': binascii.b2a_base64(npk).decode('utf8').strip(),
                 'client_sk': binascii.b2a_base64(noise_sk).decode('utf8').strip(),
                 })

   with NamedTemporaryFile(mode="w+", dir=os.path.dirname(cfg_file), delete=False, delete_on_close=False) as tmpfile:
       tname = tmpfile.name
       tomlkit.dump(cfg, tmpfile)
   os.replace(tname, cfg_file);
   print(f'please add {binascii.b2a_base64(spk+npk).decode().strip()} to all other klutshnikd servers authorized_keys files you intend to use in a group')

def main():
   PORT = "/dev/ttyACM0"
   cfg_file = None
   uart=False
   esp=False

   # parse args
   for arg in sys.argv[1:]:
      if arg.startswith('/dev/'):
         PORT=arg
      elif arg.endswith('.cfg'):
         cfg_file = arg
      elif arg.endswith('authorized_keys'):
         with open(arg,'r') as fd:
            authkeys=[binascii.a2b_base64(line.strip()) for line in fd]
      elif arg=='uart':
         uart=get_serial(PORT)
      elif arg=="esp":
         esp=True

   with open(cfg_file,'rb') as fd:
       cfg = tomlkit.load(fd)

   # reset device
   if esp:
      with detect_chip(PORT) as esp:
         esp.connect()
         esp.hard_reset()

   serialPort = serial.Serial(port=PORT, baudrate=115200)
   for _ in range(100):
      line = serialPort.readline().decode("Ascii").strip()
      if debug: print(line)
      if 'no configuration found. waiting for initialization' in line:
         ltsigpub = binascii.a2b_base64(cfg['client']['ltsigpub'][8:])
         noise_sk = randombytes(32)
         noise_pk = noisexk.pubkey(noise_sk)
         msg = ltsigpub+noise_pk+struct.pack("B",len(authkeys))+b''.join(authkeys)
         serialPort.write(b'KLUTSHNIK-DEVICE-INIT'+struct.pack("!H", len(msg))+msg)
         break
   else:
       raise ValueError("unexpected initialization")

   # collect info
   npk=None
   spk=None
   mac=None
   for _ in range(100):
      line = serialPort.readline().decode("Ascii").strip()
      if debug: print(line)
      if '<inf> klutshnik: noise pk' in line:
         npk=binascii.a2b_base64(line.split()[-1])
      if '<inf> klutshnik: ltsig pk' in line:
         spk=binascii.a2b_base64(line.split()[-1])
      if '<inf> klutshnik: MAC address:' in line:
         mac=line.split()[-2]
      if spk is not None and npk is not None and (uart is not None or mac is not None):
         return write_cfg(cfg, cfg_file, mac,spk,npk, noise_sk, uart)
   if uart is None:
      print('failed to fetch the pubkeys and mac')
   else:
      print('failed to fetch the pubkeys')

if __name__ == '__main__':
    main()
