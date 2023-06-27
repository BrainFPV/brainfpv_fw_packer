# BrainFPV Firmware Packer
Utility for packing firmware for BrainFPV devices

Installation
------------

pip install git+https://github.com/BrainFPV/brainfpv_fw_packer.git

Example Usage
-------------

Compress a hex file for use on a RADIX 2 flight controller:

    brainfpv_fw_packer.py \
       --name "My firmware" \
       --version 0.1 \
       --dev radix2 \
       --t firmware \
       --boot 0x90400000 \
       --zip \
       --in firmware.hex \
       --out firmware_packed.bin

To use the resulting `firmware_packed.bin` file, copy it to the RADIX 2
as described [here](https://www.brainfpv.com/knowledgebase/installing-firmware-with-the-brainfpv-bootloader/).
