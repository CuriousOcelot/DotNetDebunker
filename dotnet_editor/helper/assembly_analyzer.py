from __future__ import annotations

import hashlib
import io
import os
from typing import List, Dict, Tuple

import lief

from config import TMP_PATH
from dotnet_editor.data_classes.dotnet_method import DotNetMethod
from dotnet_editor.data_classes.local_var_sig_info import LocalVarSigInfo
from dotnet_editor.data_classes.method_def_info import MethodDefInfo
from dotnet_editor.helper.pe_reader import PEModel
from dotnet_editor.utility.dn_edit_util import get_local_var_sig, rva_to_file_offset
from dotnet_editor.utility.utility import int_to_hex, int_list_to_hex_list, info_logging_with_no_line_num, \
    error_logging_with_no_line_num, debug_logging_with_no_line_num


class AssemblyAnalyzer:
    def __init__(self, pe_model: PEModel, flag_new_sec_auto_sizing):
        self._new_section_va = None
        self._new_section_raw = None
        self.new_method_offset = 0
        self._pe_model: PEModel = pe_model
        self._flag_new_sec_auto_sizing: bool = flag_new_sec_auto_sizing
        self._method_map: Dict[Tuple[int, str], MethodDefInfo] = {}
        self._local_var_sig_map: Dict[str, LocalVarSigInfo] = {}

    def is_new_section_added(self):
        if self._new_section_va is None or self._new_section_va is None:
            return False
        return True

    @property
    def method_map(self):
        return self._method_map

    @property
    def local_var_sig_map(self):
        return self._local_var_sig_map

    @property
    def new_section_va(self):
        return self._new_section_va

    @property
    def new_section_raw(self):
        return self._new_section_raw

    def get_byte(self, addr):
        return self._pe_model.get_byte(addr)

    def analyze(self):
        info_logging_with_no_line_num("[*] Analyze assembly")

        # lets analyze the method and its parametre using dnllib
        dnlib_method_detail: Dict[int:DotNetMethod] = {}

        for type_def in self._pe_model.dnlib_module.GetTypes():
            for dnlib_method in type_def.Methods:
                md_token = dnlib_method.MDToken.get_Raw()
                param_types = []
                is_static_method = None
                for param in dnlib_method.Parameters:
                    if param.get_IsHiddenThisParameter():
                        if is_static_method is None:
                            is_static_method = False  # because it is this parametre
                        continue
                    else:
                        if is_static_method is None:
                            is_static_method = True  # because it is this parametre
                        param_types.append(param.Type.FullName)
                if is_static_method is None:
                    is_static_method = True

                dnlib_method_detail[md_token] = DotNetMethod(
                    md_token,
                    type_def.FullName,
                    dnlib_method.Name,
                    param_types,
                    is_static_method,
                )

        rvas_seen = set()
        method_def_table = self._pe_model.dnfile_pe.net.mdtables.MethodDef
        if not method_def_table:
            print("No MethodDef table found")
        method_table_addr = method_def_table.file_offset
        method_def_table_row_size = method_def_table.row_size
        method_table_addr -= method_def_table_row_size
        for i in range(len(method_def_table.rows)):
            method_table_addr += method_def_table_row_size
            token = 0x06_00_00_00 + 0x01 + i
            method_row = method_def_table.rows[i]

            rva = method_row.Rva
            name_offset = method_row.Name
            # Compose full method name string
            method_name = name_offset.value
            sig = method_row.Signature.value
            if sig[0] == 0x20:
                flag_is_static_method = False
            else:
                flag_is_static_method = True

            dotnet_method: DotNetMethod = dnlib_method_detail[token]
            # validation
            if token == dotnet_method.md_token and method_name == dotnet_method.method_name and flag_is_static_method == dotnet_method.is_static_method:
                pass
            else:
                error_logging_with_no_line_num("Dnlib method dont match with dnfile")
                raise Exception("Dnlib method dont match with dnfile")

            if rva == 0:
                continue
            try:
                ra = rva_to_file_offset(self._pe_model.dnfile_pe, rva)
            except Exception as e:
                print(f"Could not convert RVA {rva}: {e}")
                continue
            method_code_data = self._pe_model.dnfile_pe.get_data(rva, 16)
            if not method_code_data:
                continue
            first_byte = method_code_data[0]
            format_type = first_byte & 0x03
            if format_type == 2:
                # Tiny header
                code_size = first_byte >> 2
                il_offset = 1
            elif format_type == 3:
                # Fat header
                code_size = int.from_bytes(method_code_data[4:8], byteorder='little')
                il_offset = 12
            else:
                code_size = 0
                il_offset = 1
            rva_duplicated = rva in rvas_seen
            method_def_info = MethodDefInfo(
                token=token,
                prva_addr=rva,
                method_name=method_name,
                method_il_code_addr=ra + il_offset,
                method_il_code_size=code_size,
                rva_duplicated=rva_duplicated,
                method_table_addr=method_table_addr,  # dnfile does not expose method table address directly
                dotnet_method=dotnet_method
            )
            if (token, dotnet_method.full_method_name) in self._method_map:
                raise Exception(f"Duplicate method for : {dotnet_method.full_method_name}")
            self._method_map[(token, dotnet_method.full_method_name)] = method_def_info
            rvas_seen.add(rva)
        # lets do for local variable sig map
        stand_along_sig_table = self._pe_model.dnfile_pe.net.mdtables.StandAloneSig
        if not stand_along_sig_table:
            print("No StandAloneSig table found")

        for i in range(len(stand_along_sig_table.rows)):
            row = stand_along_sig_table.rows[i]
            signature = row.Signature
            value = signature.value
            token = 0x11000000 | (i + 1)
            l = LocalVarSigInfo(token, value)
            sha1_value = hashlib.sha1(value).hexdigest()
            self._local_var_sig_map[sha1_value] = l
        pass

    def get_ilcode(self, method: MethodDefInfo, index: int):
        ilcode_addr = method.method_il_code_addr
        return self._pe_model.get_byte(ilcode_addr + index)

    def write_bytearray_at(self, addr, data: bytearray):
        for num in range(len(data)):
            self.write_byte_at(addr + num, data[num])

    def write_byte_at(self, addr, byte_to_write):
        self._pe_model.write_byte_at(addr, byte_to_write)
        pass

    def create_new_section(self):
        if self.new_method_offset != 0:
            raise Exception(
                f"Seems like create_new_section() called twice. [new_method_offset = {self.new_method_offset}]")
        pe_data_bytearray = self.get_whole_data(True)

        pe = lief.PE.parse(io.BytesIO(pe_data_bytearray))
        section = lief.PE.Section(".ljp")

        if self._flag_new_sec_auto_sizing:
            total_byte_len = len(self._pe_model.get_whole_data())
            new_sec_size = ((total_byte_len // 0x1000) + 1) * 0x1000  # lets macke section size same as that of the data
            section.content = [0x00] * int(new_sec_size)
        else:
            section.content = [0x00] * 0x1000  # 4KB of zeroed bytes
        section.characteristics = (
            0x60000020  # MEM_READ | MEM_EXECUTE | CNT_COD
        )
        pe.add_section(section, lief.PE.SECTION_TYPES.TEXT)
        ljp_tmp_path = os.path.join(TMP_PATH, "ljp.tmp")
        pe.write(ljp_tmp_path)

        pe_file = PEModel.open_packed_file(ljp_tmp_path)
        self._pe_model = pe_file
        self._method_map: Dict[int, MethodDefInfo] = {}
        self._local_var_sig_map: Dict[str, LocalVarSigInfo] = {}
        self.analyze()
        os.remove(ljp_tmp_path)  # delete the temp file

        # Set PEStruct.newSectionRaw & PEStruct.newSectionVA
        base_addr = 0
        nt_hdr_addr = base_addr + self._pe_model.read_uint_t(base_addr + 0x3c)
        section_count = self._pe_model.read_ushort_t(nt_hdr_addr + 0x06)
        optional_hdr_size = self._pe_model.read_ushort_t(nt_hdr_addr + 0x14)
        optional_hdr_addr = nt_hdr_addr + 0x18
        section_hdr_addr = optional_hdr_addr + optional_hdr_size
        for num in range(section_count):
            section_hdr_value = self._pe_model.read_stringlike_bytes(section_hdr_addr)
            if section_hdr_value == b".ljp":
                self._new_section_raw = self._pe_model.read_uint_t(section_hdr_addr + 0x14)
                self._new_section_va = self._pe_model.read_uint_t(section_hdr_addr + 0x0c)
            section_hdr_addr += 0x28

    def get_whole_data(self, as_copy: bool = False):
        return self._pe_model.get_whole_data(as_copy=as_copy)
        pass


if __name__ == '__main__':
    import sys

    if len(sys.argv) > 1:
        file_path = sys.argv[1]
    else:
        print("No file path argument pass")
        sys.exit(1)
    pe_file = PEModel.open_packed_file(file_path)
    assembly_analyzer = AssemblyAnalyzer(pe_file, False)
    assembly_analyzer.analyze()
