# Klutshnik-Zephyr

This is an experimental port of the [klutshnik](https://klutshnik.info) server to zephyr OS.

## Suppported boards

 - Bluetooth LE [xiao esp32s3](https://www.tme.eu/it/en/details/seeed-113991114/development-kits-for-data-transmission/seeed-studio/xiao-esp32s3/) (probably anything based on an ESP32s3) - very small, very cheap (~9eur), quite performant.
 - USB (CDC-ACM) [teensy 4.[01]](https://www.pjrc.com/store/teensy41.html) - smallish, but quite expensive (~26/34eur), very fast.
 - USB (CDC-ACM) [raspberry pico2](https://www.raspberrypi.com/documentation/microcontrollers/pico-series.html#pico-2-family) (probably anything using an rp2350) - smallish, very cheap (~7 eur/9 eur with BLE), lot's of hw security features (to be used)

## Features

 - works transparently with liboprf>=v0.9.0 over Bluetooth LE or USB CDC-ACM (UART)
 - all klutshnik/test/test.sh tests complete successfully

## Building

### Dependencies:
 - `pip install west pyserial tomlkit pyudev pysodium pyoprf`

If you target an ESP32 device you also need:
 - `pip install esptool`
 - `xtensa-esp32s3-elf` cross-compiler toolchain

If you target a teensy you also need:
 - [teensy loader cli version](https://www.pjrc.com/teensy/loader_cli.html)
 - and the `arm-none-eabi` cross-compiler toolchain.

For the Raspberry Pico2:
 - you currently need this [patch](https://github.com/xudongzheng/zephyr/commit/4c3c8b23ccdd81106d6444199feb45c9b8c2055a.patch) to get the RNG working, apply this in the zephyr directory
 - you also need the `arm-none-eabi` cross-compiler toolchain.

### Initializing your zephyr workspace

```sh
west init -m https://github.com/stef/klutshnik-zephyr workspace
cd workspace
west update
west blobs fetch hal_espressif hal_infineon
cd klutshnik-zephyr
```

You need the hal_espressif blobs for the esp32s3 based builds, and the hal_infineon blobs for the raspberry pico 2w based builds.

### Building the images

If you are building for the xiao_esp32s3:
```
FILE_SUFFIX=ble \
   ZEPHYR_TOOLCHAIN_VARIANT=cross-compile \
   CROSS_COMPILE=/usr/bin/xtensa-esp32s3-elf- \
   west build -p auto -b xiao_esp32s3/esp32s3/procpu klutshnik -DCONFIG_KLUTSHNIK_BLE=y
```

And if you are building for the teensy 4.x:
```
FILE_SUFFIX=uart \
   ZEPHYR_TOOLCHAIN_VARIANT=cross-compile \
   CROSS_COMPILE=/usr/bin/arm-none-eabi- \
   west build -p auto -b teensy41 klutshnik -DCONFIG_KLUTSHNIK_USB_CDC=y
```

replace `teensy41` with `teensy40` if needed.

Building for the Raspberry Pico2:
```
FILE_SUFFIX=uart \
   ZEPHYR_TOOLCHAIN_VARIANT=cross-compile \
   CROSS_COMPILE=/usr/bin/arm-none-eabi- \
   west build -p auto -b rpi_pico2/rp2350a/m33 klutshnik -DCONFIG_KLUTSHNIK_USB_CDC=y
```

### Flashing the images

Flashing - assuming your xiao_esp32s3 is connected via USB and mapped to /dev/ttyACM0:

```sh
west flash --esp-device=/dev/ttyACM0
```

Just omit the ``--esp-device` param and it will autoprobe, though it will be a bit slower.

With a teensy it's simpler - if you have the teensy cli loader:

```sh
west flash
```

## Provisioning a new device

Before using your klutshnik device, you must provision
it. This is done by connecting your device via USB and running:

```sh
python provision-ble.py /dev/ttyACM0 test/klutshnik.cfg test/servers/authorized_keys uart
```

or if you use an ESP32s3 based device:

```sh
python provision-ble.py /dev/ttyACM0 test/klutshnik.cfg test/servers/authorized_keys esp
```

The `/dev/ttyACM0` value is a default, you can leave it out, if your
device is connected to this port. The other two can also be real
configuration files, not only test configs. However make sure that the
`authorized_keys` file contains all other devices already you want to
use, otherwise you have to add them manually using the USB serial shell.

At the end of the provisioning the script outputs a value, that needs
to be added to the `authorized_keys` file of all the other klutshnik
servers in the setup you want to use. In the test-case appending this
to the file `test/servers/authorized_keys` should do the trick.

## Manual Device Configuration

The `provision-ble.py` should get you all set up. But if you later
have to do some reconfiguration - klutshnik-zephyr comes with a USB
UART shell that allows you to do this manually. For klutshnik devices
that use USB for communication, there is always two serial ports
created the first is the management port with the shell and the log,
and the second port is always the klutshnik protocol port. So if you
have both `/dev/ttyACM0` and `/dev/ttyACM1` then the shell is on
`/dev/ttyACM0`

The following commands are supported:

Set the owners client ltsig public key (currently unused): `init ltsig <base64 ltsig pubkey>`

Set the owners client noise public key (also currently unused): `init noise <base64 ltsig pubkey>`

Check if the initial provisioning is complete (init ltsig/noise done,
and at least 3 entries in the authorized_keys file): `init check`

Add a new entry to the `authorized_keys` file: `authkey add <base64 authkey entry>`

Delete the `authorized_keys` file: `authkey del`

Get the contents of the `authorized_keys` file: `authkey get`

Get the devices ltsig public key: `getcfg ltsig`

Get the devices noise public key: `getcfg noise`

Get the devices MAC - if the device uses Bluetooth LE as the
communication layer: `getcfg mac`

## Testing

The git repo ships a configured 5-way setup in `test/` with one HW device.

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

or you could just use plain old socat
```sh
socat /dev/ttyACM0,b115200,raw,echo=0 -,escape=0x0f
```

Finally you can start running the tests, for this you need to have the
klutshnik client installed on your path (python virtual env suffices):

```sh
cd test
rm -rf otherclient/keystore/[0-9a-f]*
./test.sh
```
## Roadmap

 - support more boards
 - interface for configuring the device after provisioning (authorized_keys management, other key mgt)
 - somewhere in the far future perhaps also support WiFi as a medium.

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
