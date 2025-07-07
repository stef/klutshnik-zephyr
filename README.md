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

Before using your ESP32s3-based klutshnik device, you must provision
it. This is done by connecting your device via USB and running:

```sh
python provision-ble.py /dev/ttyACM0 test/klutshnik.cfg test/servers/authorized_keys
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
 - interface for configuring the device after provisioning (authorized_keys managment, other key mgt)
 - somewhere in the far future perhaps also support WiFi as a medium.

## Funding

This project is funded through [NGI0 Entrust](https://nlnet.nl/entrust), a fund
established by [NLnet](https://nlnet.nl) with financial support from the
European Commission's [Next Generation Internet](https://ngi.eu) program. Learn
more at the [NLnet project page](https://nlnet.nl/project/ThresholdOPRF).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)
[<img src="https://nlnet.nl/image/logos/NGI0_tag.svg" alt="NGI Zero Logo" width="20%" />](https://nlnet.nl/entrust)
