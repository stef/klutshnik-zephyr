#!/usr/bin/env python

import serial, binascii, sys
from esptool.cmds import detect_chip

PORT = "/dev/ttyACM0"
if(len(sys.argv)>1):
    PORT=sys.argv[1]

with detect_chip(PORT) as esp:
    esp.connect()
    esp.hard_reset()
    serialPort = serial.Serial(port=PORT, baudrate=115200)
    npk=None
    spk=None
    mac=None
    for _ in range(100):
        line = serialPort.readline().decode("Ascii").strip()
        if '<inf> klutshnik: noise pk' in line:
            npk=binascii.a2b_base64(line.split()[-1])
            pass
        if '<inf> klutshnik: ltsig pk' in line:
            spk=binascii.a2b_base64(line.split()[-1])
        if '<inf> klutshnik: MAC address:' in line:
            mac=line.split()[-2]
        if spk is not None and npk is not None and mac is not None:
            print(f'add this to your clients klutshnik.cfg:\n\tbleaddr="{mac}"\n\tltsigkey="{binascii.b2a_base64(spk).decode('utf8').strip()}"')
            print(f"and this to your authorized_keys file: {binascii.b2a_base64(spk+npk).decode('utf8').strip()}")
            exit(0)
print('failed to fetch the pubkeys')
