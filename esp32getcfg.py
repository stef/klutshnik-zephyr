#!/usr/bin/env python

import serial, binascii, sys
from esptool.cmds import detect_chip
from pysodium import crypto_generichash

authkeys = ["8uH0+rR5KNdbJPr7+ARObHPEu4V/d6qqqDxhesjl2cihAAjmVMwvcbB+LhQvO7AF7BQW92p+xQPbFhqCoX8vNA==",
            "zy9ceExzhXB8zK9FQwv7joZsVXTfI2p+DEMZYyG96ukLdq7mJMyZk5lje0WF6OYaHC/CCJdABfh8rbGe3JtqBQ==",
            "zQTzmBGRHQEBhOfOBN3QYcs2qLCoU4F3zwrwTeBsDFTFjYU8r9y8MWMPOtBc8U995bACnP/JQy4l2/Ioh/IlIA==",
            "4cBhEnYZOKcacdAHyjgU57wdGAWi2WCx0cnNmrjYb4DbBdVPrm6mEwtCZN2RvTlQcUmG5+F06X3H9K0nbjTYZA==",
            "7i1i4coNfEuagd6liQ5mXPPzgUdMlEQs3w7Yf12/WN5BS+LPpwP+99nD4yjXkpEBrHX7EeQso9jABAR3ujW1Aw=="]

PORT = "/dev/ttyACM0"
if(len(sys.argv)>1):
    PORT=sys.argv[1]

def hexbytes(b):
    return ', '.join(f"0x{c:02x}" for c in b)

def output(mac, spk, npk):
    snpk = binascii.b2a_base64(spk+npk).decode('utf8').strip()
    print(f'1. Update "test/klutshnik.cfg" with:\n    bleaddr="{mac}"\n    ltsigkey="{binascii.b2a_base64(spk).decode('utf8').strip()}"')
    print(f'2. Replace the last line of "test/servers/authorized_keys" with: {snpk}')

    with open("klutshnik/src/authorized_keys.c", 'w') as fd:
        print("static const AuthKeys authkeys[] = {", file=fd)
        print(',\n'.join(
             f'   {{ .keyid = {{ {hexbytes(crypto_generichash(binascii.a2b_base64(k)[:32]))} }},\n'
             f'     .ltsig = {{ {hexbytes(binascii.a2b_base64(k)[:32])} }},\n'
             f'     .noise = {{ {hexbytes(binascii.a2b_base64(k)[32:])} }}}}'
            for k in authkeys+[snpk]
        ), file=fd)
        print("};", file=fd)
    print('3. Regenerated "klutshnik/src/authorized_keys.c", please recompile the firmware and flash your device using')
    print(f'    ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/xtensa-esp32s3-elf- west build -p auto -b xiao_esp32s3/esp32s3/procpu klutshnik && west flash --esp-device={PORT}')
    print(f'    west flash --esp-device={PORT}')
    exit(0)

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
            output(mac,spk,npk)
print('failed to fetch the pubkeys')


