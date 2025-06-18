from __future__ import annotations

import logging
import struct
from typing import TYPE_CHECKING, Dict, List, Tuple

import dnfile

from dotnet_editor.data_classes.corilmethod_fatformat import CorILMethod_FatFormat
from dotnet_editor.data_classes.corimethod_sect_ehtable import CorILMethod_Sect_EHTable
from dotnet_editor.utility.utility import info_logging_with_no_line_num, error_logging_with_no_line_num

if TYPE_CHECKING:
    from dotnet_editor.helper.assembly_analyzer import AssemblyAnalyzer
    from dotnet_editor.method_detail import MethodDetail
    from dotnet_editor.eh_clause import EhClause
from dotnet_editor.data_classes.corinfo_eh_clause import CORINFO_EH_CLAUSE
from dotnet_editor.data_classes.method_def_info import MethodDefInfo
from dotnet_editor.utility.logger_util import getlogger

logger = getlogger(__name__, logging.DEBUG)


def get_local_var_sig(psig_full) -> bytearray:
    psig_lb_00, psig_lb_01, psig_lb_02, psig_lb_03 = psig_full[:4]
    if (psig_lb_00 & 0x80) == 0:
        psig_len = psig_lb_00
        psig_index = 1
    elif (psig_lb_00 & 0xc0) == 0x80:
        psig_len = ((psig_lb_00 & 0x3f) << 8) + psig_lb_01
        psig_index = 2
    else:
        psig_len = ((psig_lb_00 & 0x1f) << 24) + (psig_lb_01 << 16) + (psig_lb_02 << 8) + psig_lb_03
        psig_index = 4
    new_psig = psig_full[psig_index:psig_index + psig_len]
    return new_psig


def create_new_method_body_tiny(assembly_analyzer: 'AssemblyAnalyzer', info: 'MethodDetail'):
    rva = assembly_analyzer.new_section_va + assembly_analyzer.new_method_offset
    header = bytearray()
    header.append((info.il_codes_size << 2) | 0x02)
    pos = assembly_analyzer.new_section_raw + assembly_analyzer.new_method_offset

    assembly_analyzer.write_bytearray_at(pos, header)
    assembly_analyzer.write_bytearray_at(pos + len(header), bytearray(info.il_codes))

    assembly_analyzer.new_method_offset = assembly_analyzer.new_method_offset + len(header) + info.il_codes_size

    return rva


def create_new_method_body_fat(
        assembly_analyzer: 'AssemblyAnalyzer',
        info: 'MethodDetail',
        local_var_sig_tok: int,
        eh_clause_details: List[CORINFO_EH_CLAUSE]
):
    rva = assembly_analyzer.new_section_va + assembly_analyzer.new_method_offset
    eh_table: CorILMethod_Sect_EHTable = None
    total_eh_clause_bytes = bytearray()

    header_flag = 0x03 | 0x10 | 0x3000

    if info.eh_count > 0:
        flag_eh_count = True
    else:
        flag_eh_count = False

    if flag_eh_count:
        header_flag |= 0x08
        flag_is_fat_eh_clause = False
        for eh_clause in eh_clause_details:
            if not eh_clause.can_be_tiny():
                flag_is_fat_eh_clause = True
                break

        if flag_is_fat_eh_clause:
            clause_size = info.eh_count * 24  # fat clauses are 24 bytes
            section_kind = 0x41  # CorILMethod_Sect_FatFormat | CorILMethod_Sect_EHTable
        else:
            clause_size = info.eh_count * 12  # tiny clauses are 12 bytes
            section_kind = 0x01  # CorILMethod_Sect_EHTable (tiny format)

        eh_table = CorILMethod_Sect_EHTable(
            section_kind, 4 + clause_size, 0, eh_clause_details
        )
        for eh_clause in eh_clause_details:
            if flag_is_fat_eh_clause:
                total_eh_clause_bytes.extend(eh_clause.to_fat_bytes())
            else:
                total_eh_clause_bytes.extend(eh_clause.to_tiny_bytes())

    header: CorILMethod_FatFormat = CorILMethod_FatFormat(
        header_flag,
        info.max_stack,
        info.il_codes_size,
        local_var_sig_tok
    )

    base = assembly_analyzer.new_section_raw + assembly_analyzer.new_method_offset
    offset = 0
    # Algn 4-byte
    padding = 0
    if assembly_analyzer.new_method_offset % 4 > 0:
        padding = 4 - assembly_analyzer.new_method_offset % 4

    assembly_analyzer.write_bytearray_at(base, bytearray([0] * padding))
    offset += padding
    rva += padding
    # copy header and ILCode
    header_bytes = bytearray(header.to_bytes())
    assembly_analyzer.write_bytearray_at(base + offset, header_bytes)
    offset += len(header_bytes)
    assembly_analyzer.write_bytearray_at(base + offset, bytearray(info.il_codes))
    offset += info.il_codes_size

    if flag_eh_count:
        # allign 4-byte
        padding = 0
        if info.il_codes_size % 4 > 0:
            padding = 4 - info.il_codes_size % 4

        assembly_analyzer.write_bytearray_at(base + offset, bytearray([0] * padding))
        offset += padding

        eh_table_bytes = bytearray(eh_table.to_bytes())
        assembly_analyzer.write_bytearray_at(base + offset, eh_table_bytes)
        offset += len(eh_table_bytes)

        assembly_analyzer.write_bytearray_at(base + offset, total_eh_clause_bytes)
        offset += len(total_eh_clause_bytes)

    assembly_analyzer.new_method_offset = assembly_analyzer.new_method_offset + offset
    return rva


def create_new_method_body(
        assembly_analyzer: 'AssemblyAnalyzer',
        info: 'MethodDetail',
        eh_clause_details: Dict[Tuple[int, int], 'EhClause']
):
    flag_fat_method = False
    local_var_sig_tok = 0
    clauses: List[CORINFO_EH_CLAUSE] = []

    if len(info.psig) > 0:
        # There are local variables
        local_var_sig_sha1 = info.psig_sha1_sum
        if local_var_sig_sha1 not in assembly_analyzer.local_var_sig_map:
            logger.error(f"[*] localVarSig [sha1: {local_var_sig_sha1}] not found.")

        else:
            flag_fat_method = True
            local_var_sig_tok = assembly_analyzer.local_var_sig_map[local_var_sig_sha1].token
            logger.info(f"[*] localVarSigTok: {hex(local_var_sig_tok)}")

    if info.il_codes_size >= 1 << 6:
        # The method is too large to encode the size (i.e., at least 64 bytes)
        flag_fat_method = True
    if info.eh_count != 0:
        # There are extra data sections
        # Because there are exception handlers, so a extra CorILMethod_Sect_EHTable is needed
        flag_fat_method = True
        logger.info(f"[*] EHcount: {info.eh_count}")
        for num in range(info.eh_count):
            unique_eh_key = (info.method_token, num)
            if unique_eh_key not in eh_clause_details:
                # error_logging_with_no_line_num(f"Eh clause not found for: [{info.method_token_hex}, {num}]")
                # break
                raise Exception(f"Eh clause not found for: [{info.method_token_hex}, {num}]")
            eh_clause: EhClause = eh_clause_details[unique_eh_key]
            clauses.append(eh_clause.corinfo_eh_clause())

            info_logging_with_no_line_num("")
            info_logging_with_no_line_num(f"[*] CORINFO_EH_CLAUSE:")
            info_logging_with_no_line_num(f"[*] Flags     : {clauses[num].Flags}")
            info_logging_with_no_line_num(f"[*] TryOffset : {hex(clauses[num].TryOffset)}")
            info_logging_with_no_line_num(f"[*] TryLength : {hex(clauses[num].TryLength)}")
            info_logging_with_no_line_num(f"[*] HdlOffset : {hex(clauses[num].HandlerOffset)}")
            info_logging_with_no_line_num(f"[*] HdlLength : {hex(clauses[num].HandlerLength)}")
            info_logging_with_no_line_num(f"[*] CToken    : {hex(clauses[num].ClassToken)}")

            pass

    if flag_fat_method:
        rva = create_new_method_body_fat(assembly_analyzer, info, local_var_sig_tok, clauses)
    else:
        rva = create_new_method_body_tiny(assembly_analyzer, info)  # create_new_method_body_tiny is also worked

    return rva


def modify_method(
        token,
        method_full_name,
        assembly_analyzer: 'AssemblyAnalyzer',
        method: 'MethodDefInfo',
        info: 'MethodDetail',
        eh_clause_details: Dict[Tuple[int, int], 'EhClause'],
        flag_force_new_section=False
):
    # Check whether the IL has been edited
    if info.il_codes_size == method.method_il_code_size:
        num = 0
        for num in range(info.il_codes_size):
            ilcode = info.il_codes[num]
            analyzed_ilcode = int(assembly_analyzer.get_ilcode(method, num))
            if ilcode != analyzed_ilcode:
                break

        if num == method.method_il_code_size - 1:
            return

    logger.critical("\t[+] IL has been edited!")
    if info.il_codes_size > method.method_il_code_size or method.rva_duplicated or flag_force_new_section:
        # Add new section if not added
        if not assembly_analyzer.is_new_section_added():
            assembly_analyzer.create_new_section()
            if not assembly_analyzer.is_new_section_added():
                raise Exception("New section cannot be added")
        else:
            pass

        # Make the IL live in the new section
        il_addr = create_new_method_body(assembly_analyzer, info, eh_clause_details)
        if il_addr < 0:
            return
        # Re-find method
        new_method = assembly_analyzer.method_map[(token, method_full_name)]
        new_method.prva_addr = il_addr
        # write to assemby
        il_addr_data_bytes = bytearray(struct.pack("<I", il_addr))  # < = little-endian, I = uint32_t
        assembly_analyzer.write_bytearray_at(new_method.method_table_addr, il_addr_data_bytes)

        pass
    else:
        assembly_analyzer.write_bytearray_at(method.method_il_code_addr,
                                             bytearray(info.il_codes))  # this wone easily work
    pass


def rva_to_file_offset(pe: dnfile.dnPE, rva: int) -> int:
    for section in pe.sections:
        start_rva = section.VirtualAddress
        size = section.SizeOfRawData
        if start_rva <= rva < start_rva + size:
            offset = (rva - start_rva) + section.PointerToRawData
            return offset
    raise ValueError(f"RVA 0x{rva:X} not found in any section.")


def parse_ftn_dump(dump_str):
    result = {}
    for line in dump_str.strip().split("\n"):
        if ": " in line:
            key, value = line.split(": ", 1)
            result[key.strip()] = value.strip()
    return result
