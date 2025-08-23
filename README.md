# Klutshnik-Zephyr

This is an experimental port of the klutshnik server to zephyr os.

## Suppported boards

 - BLE [xiao esp32s3](https://www.tme.eu/it/en/details/seeed-113991114/development-kits-for-data-transmission/seeed-studio/xiao-esp32s3/)
 - UART [teensy 4.1](https://www.pjrc.com/store/teensy41.html) (probably also the 4.0)
 - UART [raspberry pico2](https://www.raspberrypi.com/documentation/microcontrollers/pico-series.html#pico-2-family) (probably anything using an rp2350)

## Features

 - works transparently with liboprf>=v0.8.0 over Bluetooth LE or USB CDC-ACM (UART)
 - all klutshnik/test/test.sh tests complete successfully

## Building

### Dependencies:
 - `pip install west pyserial`

If you target an ESP32 device you also need:
 - `pip install esptool`
 - `xtensa-esp32s3-elf` cross-compiler toolchain

If you target a teensy you also need:
 - [https://www.pjrc.com/teensy/loader_cli.html](teensy loader cli version)
 - and the `arm-none-eabi` cross-compiler toolchain.

For the Raspberry Pico2:
 - you currently need this [patch](https://github.com/xudongzheng/zephyr/commit/4c3c8b23ccdd81106d6444199feb45c9b8c2055a.patch) to get the RNG working, apply this in the zephyr directory
 - you also neeed the `arm-none-eabi` cross-compiler toolchain.

### Initializing your zephyr workspace

```sh
west init -m https://github.com/stef/klutshnik-zephyr workspace
cd workspace
west update
west blobs fetch hal_espressif hal_infineon
cd klutshnik-zephyr
```

You need hal_espressif for the esp32s3 based builds, and the hal_infineon for the raspberry pico 2w based builds.

### Building the images

If you are building for the xia_esp32s3:
```
FILE_SUFFIX=ble ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/xtensa-esp32s3-elf- west build -p auto -b xiao_esp32s3/esp32s3/procpu klutshnik -DCONFIG_KLUTSHNIK_BLE=y
```

And if you are building for the teensy 4.1:
```
FILE_SUFFIX=uart ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/arm-none-eabi- west build -p auto -b teensy41 klutshnik -DCONFIG_KLUTSHNIK_USB_CDC=y
```

Building for the Raspberry Pico2:
```
FILE_SUFFIX=uart ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/arm-none-eabi- west build -p auto -b rpi_pico2/rp2350a/m33 klutshnik -DCONFIG_KLUTSHNIK_USB_CDC=y
```

and with BLE instead:

```
FILE_SUFFIX=ble ZEPHYR_TOOLCHAIN_VARIANT=cross-compile CROSS_COMPILE=/usr/bin/arm-none-eabi- west build -p auto -b rpi_pico2/rp2350a/m33 klutshnik -DCONFIG_KLUTSHNIK_BLE=y
```

### Flashing the images

Flashing - assuming your xiao is connected via usb and mapped to /dev/ttyACM0:

```sh
west flash --esp-device=/dev/ttyACM0
```

Just omit the ``--esp-device` param and it will autoprobe, and be a bit slower.

With a teensy it's simpler if you have the teensy cli loader:

```sh
west flash
```

## Testing

The repos ships a configured 5-way setup in `test/` with one BLE device.

### Configuration

Before using your ESP32s3-based klutshnik device, you must provision
it. This is done by connecting your device via USB and running:

```sh
python provision-ble.py /dev/ttyACM0 test/klutshnik.cfg test/servers/authorized_keys uart
```

or

```sh
python provision-ble.py /dev/ttyACM0 test/klutshnik.cfg test/servers/authorized_keys esp
```

The `/dev/ttyACM0` value is a default, you can leave it out, if your
device is connected to this port. The other two can also be real
configuration files, not only test configs. However make sure that the
`authorized_keys` file contains all other devices already you want to
use, since there is currently no way to add/change/delete new entries
on the device (this is an urgent todo, coming very soon).

At the end of the provisioning the script outputs a value, that needs
to be added to the `authorized_keys` file of all the other klutshnik
servers in the setup you want to use. In the test-case appending this
to the file `test/servers/authorized_keys` should do the trick.

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
 - interface for configuring the device after provisioning (authorized_keys managment, other key mgt)
 - somewhere in the far future perhaps also support WiFi as a medium.

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
