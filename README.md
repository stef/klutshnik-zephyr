# Klutshnik-Zephyr

This is an experimental port of the klutshnik server to zephyr os.

## Suppported boards

 - [xiao esp32s3](https://www.tme.eu/it/en/details/seeed-113991114/development-kits-for-data-transmission/seeed-studio/xiao-esp32s3/)

## Features

 - works transparently with liboprf>=v0.8.0 over Bluetooth LE
 - all klutshnik/test/test.sh tests complete successfully

## Building

Dependencies:
 - `pip install west esptool pyserial`
 - `xtensa-esp32s3-elf` cross-compiler toolchain.

```sh
west init -m https://github.com/stef/klutshnik-zephyr workspace
cd workspace
west update
west blobs fetch hal_espressif
cd klutshnik-zephyr
ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/xtensa-esp32s3-elf- west build -p auto -b xiao_esp32s3/esp32s3/procpu klutshnik
```

Flashing - assuming your xiao is connected via usb and mapped to /dev/ttyACM0:

```sh
% west flash --esp-device=/dev/ttyACM0
```

Just omit the ``--esp-device` param and it will autoprobe, and be a bit slower.

## Testing

The repos ships a configured 5-way setup in `test/` with one BLE device.

### Configuration

You need to add your BLE devices correct MAC address to `test/klutshnik.cfg`.
The long-term sigining and noise keys are generated automatically when they
are not available during booting. You need to fetch them using:

```sh
python esp32getcfg.py
```

Follow the instructions and make sure that when you add the line to
the `authorized_keys` file, that you **replace** the last line with the
one provided by the tool.

`esp32getcfg.py` also regenerates your
`klutshnik/src/authorized_keys.c` file, you need to recompile and
flash the new firmware image so that it is setup correctly with the
newly generated keys.

### Running the other servers

You need to have `klutshnikd` available for the TLS-based servers, run
this in a separate terminal:

```sh
cd test/servers
rm -rf */data
ORACLE=<path/to/klutshnikd> ./start-servers.sh
```

### Running the tests

As soon as you have the servers running. Power up your BLE device
using USB, optionally you can start monitoring the log of this device
using (assuming the device is available on `/dev/ttyACM0`:

```sh
west espressif monitor -p /dev/ttyACM0
```

Finally you can start running the tests, for this you need to have the
klutshnik client installed on your path (python virtual env suffices):

```sh
cd test
rm -rf otherclient/keystore/[0-9a-f]*
./test.sh
```

## Limitations

 - `authorized_keys` is statically compiled in the fw image
 - clients long-term noise and signing keys are also hard-coded in the fw.
 - long-term signing and noise keys are generated automatically and their
   public keys are exposed over the UART console

use the `esp32getcfg.py` script to work with these limitations, until
they are resolved.

## Roadmap

 - add support for USB as a communication medium
 - support more boards
 - better configuration instead of recompiling and messing with `esp32getcfg.py`
 - somewhere in the far future perhaps also support WiFi as a medium.

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
