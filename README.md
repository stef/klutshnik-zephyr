# Klutshnik-Zephyr

This is an experimental port of the klutshnik server to zephyr os.

## Suppported boards

 - xiao esp32s3

## Features

 - works transparently with liboprf>=v0.8.0 over Bluetooth LE
 - all klutshnik/test/test.sh tests complete successfully

## Building

Dependencies: 
 - west
 - `xtensa-esp32s3-elf` cross-compiler toolchain.

'''sh
git clone https://github.com/stef/klutshnik-zephyr
west init -m ./klutshnik-zephyr workspace
cd workspace
west update
west blobs fetch hal_espressif
cd klutshnik
ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/xtensa-esp32s3-elf- west build -p auto -b xiao_esp32s3/esp32s3/procpu klutshnik
```

Flashing - assuming your xiao is connected via usb and mapped to /dev/ttyACM0:

```sh
% west flash --esp-device=/dev/ttyACM0
```

Just omit the ``--esp-device` param and it will autoprobe, and be a bit slower.

## Testing

You can find a setup in the `zephyr-test-cfg` branch of the main klutshnik repo
in the `test` directory.

## Limitations

 - `authorized_keys` is statically compiled in the fw image
 - clients long-term noise and signing keys are also hard-coded in the fw.
 - long-term signing and noise keys are generated automatically and their
   public keys are exposed over the UART console

## Roadmap

 - add support for USB as a communication medium
 - support more boards
 - somewhere in the far future perhaps also support WiFi as a medium.

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
