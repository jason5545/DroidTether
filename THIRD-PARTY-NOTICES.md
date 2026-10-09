# Third-party notices

## libusb

The `droidtetherd` daemon inside DroidTether.app is statically linked with
[libusb](https://libusb.info/) 1.0.30, which is licensed under the GNU Lesser
General Public License, version 2.1 or later. The full license text is in
`libusb-COPYING.txt` next to this file (inside the app:
`DroidTether.app/Contents/Resources/Licenses/`).

- libusb source code: https://github.com/libusb/libusb/releases/download/v1.0.30/libusb-1.0.30.tar.bz2
- DroidTether source code, including the Makefile that links libusb:
  https://github.com/jason5545/DroidTether

To relink DroidTether with a modified libusb, install your libusb build where
`brew --prefix` points (or pass `BREW=/your/prefix`) and run `make app`.
