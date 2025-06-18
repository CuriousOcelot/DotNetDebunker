import logging

import dnfile
from dnfile import dnPE

from config import PATH_TO_DNLIB_DLL
from dotnet_editor.utility.logger_util import getlogger

import clr

clr.AddReference(PATH_TO_DNLIB_DLL)
from dnlib.DotNet import ModuleDefMD
from System import Byte, Array
from System.IO import MemoryStream

logger = getlogger(__name__, logging.DEBUG)


class PEModel:
    def __init__(self, data: bytearray):
        net_bytes = Array[Byte](data)
        stream = MemoryStream(net_bytes)
        self._dnlib_module = ModuleDefMD.Load(stream)

        self._dnfile_pe: dnPE = dnfile.dnPE(data=data)
        self._pe_data_bytearray: bytearray = data
        self._pe_data_len: int = len(self._pe_data_bytearray)
        self._new_section_raw = 0
        self._new_section_va = 0
        logger.info(f"[*] file length: {self._pe_data_len}")

    @property
    def dnlib_module(self) -> ModuleDefMD:
        return self._dnlib_module

    @property
    def dnfile_pe(self) -> dnPE:
        return self._dnfile_pe

    @staticmethod
    def open_packed_file(file_path: str):
        with open(file_path, 'rb') as f:
            data = bytearray(f.read())
            logger.info(f"[*] file: {file_path}")
        return PEModel(data)

    def get_byte(self, index):
        return self._pe_data_bytearray[index]

    def read_int32_t(self, addr):
        value = int.from_bytes(self._pe_data_bytearray[addr:addr + 4], byteorder='little', signed=True)
        return value

    def read_uint32_t(self, addr):
        value = int.from_bytes(self._pe_data_bytearray[addr:addr + 4], byteorder='little', signed=False)
        return value

    def read_int_t(self, addr):
        return self.read_int32_t(addr)

    def read_uint_t(self, addr):
        return self.read_uint32_t(addr)

    def read_int16_t(self, addr):
        value = int.from_bytes(self._pe_data_bytearray[addr:addr + 2], byteorder='little', signed=True)
        return value

    def read_uint16_t(self, addr):
        value = int.from_bytes(self._pe_data_bytearray[addr:addr + 2], byteorder='little', signed=False)
        return value

    def read_short_t(self, addr):
        return self.read_int16_t(addr)

    def read_ushort_t(self, addr):
        return self.read_uint16_t(addr)

    def read_ulonglong_t(self, addr):
        value = int.from_bytes(self._pe_data_bytearray[addr:addr + 8], byteorder='little', signed=False)
        return value

    def read_stringlike_bytes(self, addr) -> bytes:
        sliced = self._pe_data_bytearray[addr:]
        splited = sliced.split(b'\x00')
        return splited[0]

    def get_bytes_after(self, addr):
        return self._pe_data_bytearray[addr:]

    def write_byte_at(self, addr, byte_to_write):
        self._pe_data_bytearray[addr] = byte_to_write

    def get_whole_data(self, as_copy: bool = False):
        if as_copy:
            return self._pe_data_bytearray.copy()
        return self._pe_data_bytearray
        pass
