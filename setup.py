#!/usr/bin/env python

from setuptools import setup

setup(name='BrainFPV Firmware Packer',
      version='0.2',
      description='Packs firmware for BrainFPV bootloader',
      author='Marin Luessi',
      author_email='martin@brainfpv.com',
      packages=['brainfpv_fw_packer'],
      package_dir={'brainfpv_fw_packer':'brainfpv_fw_packer'},
      package_data={'brainfpv_fw_packer': ['devices/*.json']},
      scripts=['brainfpv_fw_packer/brainfpv_fw_packer.py'],
      install_requires=['intelhex', 'pycrc'],
     ) 
