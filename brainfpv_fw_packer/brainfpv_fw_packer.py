#!/usr/bin/env python

import os
import os.path as op
import sys
import ctypes
import json
import site

import zlib
from optparse import OptionParser

from intelhex import IntelHex
from elftools.elf.elffile import ELFFile

import pycrc.algorithms

class DeviceInfo:
    def __init__(self, device_name):
        device_name = device_name.lower()
        # Look for the device definition file in a number of places
        dev_dirs = [op.join(op.dirname(__file__), 'devices')]

        for spd in site.getsitepackages():
            dev_dirs.append(op.join(spd, 'brainfpv_fw_packer', 'devices'))

        dev_dirs.append(op.join(site.getusersitepackages(), 'brainfpv_fw_packer', 'devices'))

        dev_found = False
        for dd in dev_dirs:
            dev_fname = op.join(dd, device_name + '.json')
            if op.exists(dev_fname):
                dev_found = True
                break

        if not dev_found:
            raise RuntimeError('No device configuration for %s. Directories searched: %s'
                               % (device_name, dev_dirs))

        def num_to_int(num):
            if isinstance(num, int):
                return num
            elif isinstance(num, float):
                return int(num)
            elif isinstance(num, str):
                if num.startswith('0x'):
                    num = int(num[2:], 16)
                    return num
                elif num.endswith('K'):
                    num = int(num[:-1]) * 1024
                    return num
                else:
                    return int(num)
            else:
                raise RuntimeError('Data type not supported')

        dev_info_dict = json.load(open(dev_fname, 'rt'))
        self.device_name = device_name
        self.device_id = num_to_int(dev_info_dict['device_id'])
        self._sections = list()
        for sect in dev_info_dict['sections']:
            address = num_to_int(sect['address'])
            size = num_to_int(sect['size'])
            self._sections.append({'address': address, 'size': size})

    def get_section(self, address):
        for s in self._sections:
            if address >= s['address'] and address < s['address'] + s['size']:
                this_sect = {'address': address, 'size': s['size'] - (address - s['address'])}
                return this_sect
        raise RuntimeError('No section with address 0x%X' % address)

    def get_sections(self, address, size):
        """Get one or more sections for the data"""
        sections_found = list()
        current_address = address
        bytes_remaining = size
        while bytes_remaining > 0:
            sect = self.get_section(current_address)
            used_size = min(bytes_remaining, sect['size'])
            sections_found.append(dict(address=sect['address'], size=used_size))
            bytes_remaining -= used_size
            current_address += used_size
        return sections_found

    def __repr__(self):
        r_str = 'Device: %s ID: 0x%X\nSections:\n' % (self.device_name, self.device_id)
        sect_str = '\n'.join(['addr: 0x%X size: %d kB' % (s['address'], (s['size'] / 1024)) for s in self._sections])
        return r_str + sect_str



class BrainFPVFwPacker:
    FILE_MAGIC = 0xCACA6F6E
    FILE_VERSION = 0x00000001

    FW_TYPES = {'firmware': 1, 'bootloader': 2}

    class FileHeader(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('magic', ctypes.c_uint32),
                    ('file_version', ctypes.c_uint32),
                    ('device_id', ctypes.c_uint32),
                    ('crc', ctypes.c_uint32),
                    ('name', ctypes.c_uint8 * 16),
                    ('version', ctypes.c_uint8 * 16),
                    ('version_sha1', ctypes.c_uint8 * 40),
                    ('boot_address', ctypes.c_uint32),
                    ('type', ctypes.c_uint8),
                    ('priority', ctypes.c_uint8),
                    ('flags', ctypes.c_uint8),
                    ('number_of_sections', ctypes.c_uint8)]

    class SectionHeader(ctypes.Structure):
        _pack_ = 1
        _fields_ = [('section_start', ctypes.c_uint32),
                    ('section_length', ctypes.c_uint32),
                    ('section_type', ctypes.c_uint8)]

    def __init__(self, fname_in, device, fw_version=None, fw_sha1=None,
                 fw_prio=None, fw_type=None, fw_boot_address=None, fw_name=None,
                 compress=False, no_header=False, hex_data=None, verbose=1):
        self.fw_version = '' if fw_version is None else fw_version
        self.fw_sha1 = '' if fw_sha1 is None else fw_sha1
        self.fw_priority = 10 if fw_prio is None else int(fw_prio)
        self.fw_type = 1 if fw_type is None else self.FW_TYPES[fw_type]
        self.fw_name = 'NONE' if fw_name is None else fw_name
        self.compress = compress
        self.no_header = no_header
        self._sections = []
        self._data_transform_steps = []
        self._n_padding_bytes = 0
        self._verbose = verbose

        if fw_boot_address is not None:
            if fw_boot_address.startswith('0x'):
                self.fw_boot_address = int(fw_boot_address[2:], 16)
            elif op.exists(fw_boot_address):
                # address is in a file
                with open(fw_boot_address, 'r') as fid:
                    self.fw_boot_address = int(fid.read(), 16)
            else:
                raise RuntimeError('Entry point needs to be hex address')
        else:
            self.fw_boot_address = 0

        if device is None:
            raise RuntimeError('device is cannot be None')

        self.dev_info = DeviceInfo(device)
        print(self.dev_info)

        if self.compress:
            self._data_transform_steps.append(self._compress_data)

        if fname_in is None:
            if hex_data is not None:
                self._parse_hex(hex_data)
            else:
                return
        elif fname_in.endswith('.hex'):
            self._parse_hex(fname_in)
        elif fname_in.endswith('.elf'):
            self._parse_elf(fname_in)
        else:
            raise RuntimeError('File type not supported')

    def _parse_hex(self, fname):
        hexf = IntelHex()
        hexf.loadhex(fname)
        for (start, stop) in hexf.segments():
            address = start
            size = stop - start
            sections = self.dev_info.get_sections(address, size)
            for sect in sections:
                data=hexf[sect['address'] : sect['address'] + sect['size']].tobinarray()
                this_section = dict(start=sect['address'], data=data, stype=self.fw_type)
                self._sections.append(this_section)

    def _parse_elf(self, fname):
        with open(fname, 'rb') as fid:
            elffile = ELFFile(fid)

            elf_data = []

            for seg in elffile.iter_segments():
                if seg['p_type'] != 'PT_LOAD':
                    continue
                sec_data = bytearray()
                for sec in elffile.iter_sections():
                    if not seg.section_in_segment(sec):
                        continue
                    if sec['sh_type'] not in ('SHT_PROGBITS', 'SHT_INIT_ARRAY', 'SHT_ARM_EXIDX'):
                        continue
                    sec_data.extend(sec.data())

                size = len(sec_data)
                if size == 0:
                    continue
                if len(sec_data) != seg['p_filesz']:
                    raise RuntimeError('Size mismatch. Seg: %s' % seg)

                elf_data.append(dict(address=seg['p_paddr'], data=sec_data))

            # Sort by address, then merge sections together if possible
            elf_data.sort(key=lambda d : d['address'])

            elf_data_comb = []
            for ii,d in enumerate(elf_data):
                if ii > 0:
                    prev = elf_data_comb[-1]
                    if d['address'] == prev['address'] + len(prev['data']):
                        prev['data'].extend(d['data'])
                        continue
                elf_data_comb.append(d)


            # Create device sections
            for d in elf_data_comb:
                sections = self.dev_info.get_sections(d['address'], len(d['data']))
                pos = 0
                for sect in sections:
                    sd = d['data'][pos:pos + sect['size']]
                    this_section = dict(start=sect['address'], data=sd, stype=self.fw_type)
                    self._sections.append(this_section)
                    pos += sect['size']

    def __repr__(self):
        lines = ['device: %s' % self.dev_info.device_name,
                 'fw_name: %s' % self.fw_name,
                 'fw_version: %s' % self.fw_version,
                 'fw_sha1: %s' % self.fw_sha1,
                 'fw_priority: %s' % self.fw_priority,
                 'fw_type: %s' % self.fw_type,
                 'fw_boot_address: 0x%08X' % self.fw_boot_address,
                 'Compressed: %s' % self.compress,
                 'Use header: %s' % (not self.no_header),
                 'Sections:']
        for sec in self._sections:
            lines.append('0x%08X len: %d' % (sec['start'], len(sec['data'])))

        rep = '\n'.join(lines)
        return rep

    def _print_hex_field(self, field):
        hex_str = ' '.join('0x%02X' % field[ii] for ii in range(len(field)))
        print(hex_str)

    def _fill_field_from_str(self, field, string_in):
        arr_values = [ctypes.c_uint8(v) for v in bytearray(string_in, 'utf-8')]
        if len(arr_values) < ctypes.sizeof(field):
            for ii in range(ctypes.sizeof(field) - len(arr_values)):
                arr_values.append(ctypes.c_uint8(0))
        for ii in range(ctypes.sizeof(field)):
            field[ii] = arr_values[ii]

    def _get_flags(self):
        flags = 0
        if self.compress:
            flags |= 0x01
        if self.no_header:
            flags |= 0x02
        return flags

    def _check_data_sections(self):
        pass

    def _calc_crc32(self, data):
        crc_alg = pycrc.algorithms.Crc(width = 32, poly = 0x04c11db7,
                                       reflect_in = True, xor_in = 0xffffffff,
                                       reflect_out = True, xor_out = 0xffffffff)

        crc32 = crc_alg.bit_by_bit_fast(data)
        return crc32

    def _compress_data(self, data_in):
        n_in = len(data_in)
        data_out = zlib.compress(data_in, level=6)
        n_out = len(data_out)
        if self._verbose > 0:
            print('In: %d Out: %d Compression ratio: 1:%0.1f' % (n_in, n_out, n_in / n_out))
        return data_out

    def save(self, fname_out, fid=None):
        """ Generate output file """
        file_header = self.FileHeader()
        file_header.magic = self.FILE_MAGIC
        file_header.file_version = self.FILE_VERSION
        file_header.device_id = self.dev_info.device_id
        self._fill_field_from_str(file_header.name, self.fw_name)
        self._fill_field_from_str(file_header.version, self.fw_version)
        self._fill_field_from_str(file_header.version_sha1, self.fw_sha1)
        file_header.boot_address = self.fw_boot_address
        file_header.type = self.fw_type
        file_header.priority = self.fw_priority
        file_header.flags = self._get_flags()
        file_header.number_of_sections = len(self._sections)
        n_data_bytes = 0
        section_header_data = bytearray()
        all_section_data = bytearray()

        self._check_data_sections()

        for s in self._sections:
            sh = self.SectionHeader()
            sh.section_start = s['start']
            sh.section_length = len(s['data'])
            sh.section_type = s['stype']
            section_header_data.extend(bytearray(sh))
            all_section_data.extend(s['data'])
            n_data_bytes += sh.section_length

        assert(len(section_header_data) == file_header.number_of_sections * ctypes.sizeof(self.SectionHeader))
        assert(len(all_section_data) == n_data_bytes)

        # Combine all the data
        all_data = bytearray(file_header)
        all_data.extend(section_header_data)
        all_data.extend(all_section_data)
        # Calculate CRC32
        file_header.crc = self._calc_crc32(all_data[16:])

        if self._verbose > 0:
            print('Total header size: %d' % (len(bytearray(file_header)) + len(section_header_data)))

        # Apply data transforms to section data:
        for tf_step in self._data_transform_steps:
            all_section_data = tf_step(all_section_data)

        # Write output
        if fid is None:
            fid = open(fname_out, 'wb')
            close_file = True
        else:
            close_file = False

        fid.write(bytearray(file_header))
        fid.write(section_header_data)
        fid.write(all_section_data)
        if close_file:
            fid.close()


if __name__ == '__main__':
    parser = OptionParser()
    parser.add_option('-i', '--in', dest='fname_in',
                      help='Input file (hex or elf)', metavar='FILE')
    parser.add_option('-d', '--dev', dest='device',
                      help='Device')    
    parser.add_option('-n', '--name', dest='fw_name',
                      help='Firmware name')
    parser.add_option('-v', '--version', dest='fw_version',
                      help='Firmware version')
    parser.add_option('-s', '--sha1', dest='fw_sha1',
                      help='Firmware SHA-1')
    parser.add_option('-p', '--prio', dest='fw_prio',
                      help='Firmware priority')
    parser.add_option('-t', '--type', dest='fw_type',
                      help='Firmware type')
    parser.add_option('-b', '--boot', dest='fw_boot_address',
                      help='Firmware boot address')
    parser.add_option('-z', '--zip', action='store_true', default=False,
                      dest='compress', help='Compress data using zlib')
    parser.add_option('--noheader', action='store_true', default=False,
                      dest='noheader', help='Do not use header embedded in firmware')
    parser.add_option('-o', '--out', dest='fname_out',
                      help='Output file', metavar='FILE')

    options, args = parser.parse_args()

    packer = BrainFPVFwPacker(options.fname_in, options.device, fw_name=options.fw_name, fw_version=options.fw_version,
                              fw_sha1=options.fw_sha1, fw_prio=options.fw_prio, fw_type=options.fw_type,
                              fw_boot_address=options.fw_boot_address, compress=options.compress,
                              no_header=options.noheader)
    print(packer)
    packer.save(options.fname_out)
