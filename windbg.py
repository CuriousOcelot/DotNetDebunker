import os
import json
import hashlib
import time

import pykd
import struct

method_details = []
main_module = pykd.dbgCommand("lm1m").split('\n')[0]
print("Main module: ", main_module)
windbg_output = os.path.join(os.path.expanduser('~'), "Downloads", 'windbg_output', str(main_module))
os.makedirs(windbg_output, exist_ok=True)

# structs
CORINFO_SIG_INFO_STRUCT_FOEMATE = struct.Struct('<' + (
        'Q' * 3 +  # callConv, retTypeClass, retTypeSigClass (3 x void* => 3 x Q)
        'Q' * 5 +  # retType_flags_numArgs, sigInst0..sigInst3 (4 x uint64_t)
        'Q' * 2 +  # args, pSig (void*, uint8_t*)
        'Q' * 3  # cbSig (uint32_t*), scope (void*), token (uint32_t*)
))

# Set breakpoint
try:
    pykd.dbgCommand("bc *")  # Clear any existing breakpoints

    clrjit_base = pykd.dbgCommand("lm m clrjit").split('\n')[2].split(" ")[0].replace("`", "")
    clrjit_base_address = int(clrjit_base, 16)
    print(f"clrjit.dll address: {hex(clrjit_base_address)}")

    clr_base = pykd.dbgCommand("lm m clr").split('\n')[2].split(" ")[0].replace("`", "")
    clr_base_address = int(clr_base, 16)
    print(f"clr.dll address: {hex(clr_base_address)}")

    # Set a memory access breakpoint on the method entry point
    bp_addr_compile_method = f"{hex(clrjit_base_address + 0x7a6e0)}"

    pykd.dbgCommand(f"ba e1 {bp_addr_compile_method}")  # Adjust as necessary for your clrjit base
    print(f"[+] Breakpoint set at CILJit::compileMethod [{bp_addr_compile_method}]")

    # bp_addr_rtn_get_ehinfo = f"{hex(clr_base_address+ 0x4FBF8)}" # at return of clr base
    # bp_addr_rtn_get_ehinfo = f"{hex(clrjit_base_address+ 0x72E31)}" #before getEHinfo excecuted
    # bp_addr_rtn_get_ehinfo = f"{hex(clrjit_base_address+ 0x72E37)}" #after getEHinfo excecuted

    bp_addr_rtn_get_ehinfo = f"{hex(clrjit_base_address + 0x72E31)}"  # before getEHinfo excecuted
    bp_addr_rtn_get_ehinfo_after_step_over = f"{hex(clrjit_base_address + 0x72E31 + 0x06)}"

    pykd.dbgCommand(f"ba e1 {bp_addr_rtn_get_ehinfo}")  # Adjust as necessary for your clrjit base
    print(f"[+] Breakpoint set at return of IMethodInfo::getEhInfo [{bp_addr_rtn_get_ehinfo}]")
except Exception as e:
    print(f"[!] Failed to set breakpoint: {e}")
    exit(1)

# Loop until process exits or exception occurs
dump_sequence_counter = 0
while True:
    try:
        try:
            pykd.go()  # This might throw the HRESULT error
        except Exception as e:
            if "SetExecutionStatus failed" in str(e) or "0x80004002" in str(e):
                print(f"[!] Breaking loop: {e}")
                break
            else:
                raise e # Re-raise other unexpected exceptions

        # If we get here, the breakpoint was hit
        ip = pykd.reg("rip")
        bp_rip_addr = f"{hex(ip)}"
        if bp_rip_addr == bp_addr_compile_method:
            print("Hit at CILJit::compileMethod")
            flag_hit_at_compileMethod = True
        elif bp_rip_addr == bp_addr_rtn_get_ehinfo:
            print("Hit at return of IMethodInfo::getEhInfo")
            flag_hit_at_compileMethod = False
        else:
            print(f"******** UNKNOWN BREAKPOINT [{bp_rip_addr}]********")
            print(f"Wait for some 3 seconds...")
            time.sleep(1)  # Exceptions might trigger breakpoit... so continue after some wait
            continue
        if flag_hit_at_compileMethod:  # when compileMethod is hitted
            corinfo_method_info_addr = pykd.reg("r8")  # Second parameter is in r8

            # Offsets from CORINFO_METHOD_INFO structure # total 256 bytes
            # struct CORINFO_METHOD_INFO
            # {
            #     CORINFO_METHOD_HANDLE ftn;     // +0x00 (8)
            #     CORINFO_MODULE_HANDLE scope;   // +0x08 (8)
            #     uint8_t *ILCode;               // +0x10 (8)
            #     unsigned ILCodeSize;           // +0x18 (4)
            #     unsigned maxStack;             // +0x1C (4)
            #     unsigned EHcount;              // +0x20 (4)
            #     CorInfoOptions options;        // +0x24 (4)
            #     CorInfoRegionKind regionKind;  // +0x28 (4)
            #     // Padding to align next field (CORINFO_SIG_INFO, 8-byte aligned)
            #     uint32_t pad;                  // +0x2C (4) padding
            #     CORINFO_SIG_INFO args;         // +0x30 (0x68)
            #     CORINFO_SIG_INFO locals;       // +0x98 (0x68)
            # }; // Total: **0x100 (256 bytes)**
            corinfo_bytes = pykd.loadBytes(corinfo_method_info_addr, 0x100)  # 256
            corinfo_bytes_hex = [f"0x{b:02X}" for b in corinfo_bytes]

            addr_ftn = corinfo_method_info_addr + 0x00  # pointer (8)
            addr_scope = corinfo_method_info_addr + 0x08  # pointer (8)
            addr_il_codes_pointer = corinfo_method_info_addr + 0x10  # pointer (8)
            addr_il_code_size = corinfo_method_info_addr + 0x18  # value (4)

            addr_max_stack = corinfo_method_info_addr + 0x1C  # value (4)
            addr_eh_count = corinfo_method_info_addr + 0x20  # value (4)
            addr_options = corinfo_method_info_addr + 0x24  # value (4)
            addr_region_kind = corinfo_method_info_addr + 0x28  # value (4) # after this padding  (4)
            addr_args = corinfo_method_info_addr + 0x30  # value 104 bytes  (104)
            addr_locals = corinfo_method_info_addr + 0x98  # value 104 bytes (104)

            # Fetch method info from memory
            ftn_value_addr = pykd.loadQWords(addr_ftn, 1)[0]
            ftn_bytes = pykd.loadBytes(ftn_value_addr, 8)
            ftn_hex = [f"0x{b:02X}" for b in ftn_bytes]

            # Read pointer from R8 (CORINFO_METHOD_INFO*)
            methodHandle = pykd.ptrPtr(corinfo_method_info_addr)
            print("[*] R8 points to CORINFO_METHOD_INFO at: 0x{:016X}".format(corinfo_method_info_addr))
            print("[*] MethodDesc (ftn) pointer: 0x{:016X}".format(methodHandle))
            sosCommand = "!dumpmd 0x{:016X}".format(methodHandle)
            ftn_dumps = pykd.dbgCommand(sosCommand)

            scope_value_addr = pykd.loadQWords(addr_scope, 1)[0]
            scope_bytes = pykd.loadBytes(scope_value_addr, 8)
            scope_hex = [f"0x{b:02X}" for b in scope_bytes]

            # il codes
            il_codes_pointer_value = pykd.loadQWords(addr_il_codes_pointer, 1)[0]
            il_code_size = pykd.loadDWords(addr_il_code_size, 1)[0]  # 4-byte unsigned integer
            il_codes = pykd.loadBytes(il_codes_pointer_value, il_code_size)
            il_codes_hex = [f"0x{b:02X}" for b in il_codes]

            # max stacks
            max_stack = pykd.loadDWords(addr_max_stack, 1)[0]  # 4-byte unsigned integer
            # eh_count
            eh_count = pykd.loadDWords(addr_eh_count, 1)[0]  # 4-byte unsigned integer
            # options
            options = pykd.loadDWords(addr_options, 1)[0]  # 4-byte unsigned integer
            # region kind
            region_kind = pykd.loadDWords(addr_region_kind, 1)[0]  # 4-byte unsigned integer
            # args

            args_bytes = pykd.loadBytes(addr_args, 0x68)
            args_hex = [f"0x{b:02X}" for b in args_bytes]
            # locals
            locals_bytes = pykd.loadBytes(addr_locals, 0x68)
            locals_hex = [f"0x{b:02X}" for b in locals_bytes]

            locals_data_struct = CORINFO_SIG_INFO_STRUCT_FOEMATE.unpack(bytes(locals_bytes))
            if locals_data_struct[9] == 0:  # this may say no local variable
                psig_value_hex = []
                psig_full_hex = []
            else:
                # read psig
                # (uint8_t/uint16_t/uint64_t)(psig......)
                print(locals_data_struct)
                psig_addr_index = locals_data_struct[9] - 1
                psig_lb_00, psig_lb_01, psig_lb_02, psig_lb_03 = pykd.loadBytes(psig_addr_index, 0x04)
                if (psig_lb_00 & 0x80) == 0:
                    psig_len = psig_lb_00
                    psig_addr = psig_addr_index + 1
                    psig_manifest_len = 0x01
                elif (psig_lb_00 & 0xc0) == 0x80:
                    psig_len = ((psig_lb_00 & 0x3f) << 8) + psig_lb_01
                    psig_addr = psig_addr_index + 2
                    psig_manifest_len = 0x02
                else:
                    psig_len = ((psig_lb_00 & 0x1f) << 24) + (psig_lb_01 << 16) + (psig_lb_02 << 8) + psig_lb_03
                    psig_addr = psig_addr_index + 4
                    psig_manifest_len = 0x04

                total_byte_to_read = psig_manifest_len + psig_len
                psig_value = pykd.loadBytes(psig_addr, psig_len)
                psig_full_value = pykd.loadBytes(psig_addr_index, total_byte_to_read)
                psig_value_hex = [f"0x{b:02X}" for b in psig_value]
                psig_full_hex = [f"0x{b:02X}" for b in psig_full_value]

            detail = {
                "corinfo": corinfo_bytes_hex,
                "ftn_value": ftn_hex,
                "ftn_dumps": ftn_dumps,
                "scope_value": scope_hex,
                "il_codes": il_codes_hex,
                "il_code_size": f"0x{il_code_size:02X}",
                "max_stack": f"0x{max_stack:02X}",
                "eh_count": f"0x{eh_count:02X}",
                "options": f"0x{options:02X}",
                "region_kind": f"0x{region_kind:02X}",
                "args": args_hex,
                "locals": locals_hex,
                "psig": psig_value_hex,
                "psig_full": psig_full_hex,
            }
        else:
            # When getEHinfo get hitted
            ehinfo_ftn_value_addr = pykd.reg("rdx")  # First parameter is in rdxod
            ehinfo_ftn_bytes = pykd.loadBytes(ehinfo_ftn_value_addr, 8)
            ehinfo_ftn_hex = [f"0x{b:02X}" for b in ehinfo_ftn_bytes]

            # Read pointer from RDX (CORINFO_METHOD_INFO)
            print("[*] MethodDesc (ftn) pointer: 0x{:016X}".format(ehinfo_ftn_value_addr))
            sosCommand = "!dumpmd 0x{:016X}".format(ehinfo_ftn_value_addr)
            ftn_dumps = pykd.dbgCommand(sosCommand)

            eh_number = pykd.reg("r8d")

            corinfo_eh_clause_addr = pykd.reg("r9")

            # now lets do step over
            pykd.dbgCommand("p")
            rip = f'{hex(pykd.reg("rip"))}'
            print(f"[+] RIP after step over: {rip}")
            print(f"[+] expected RIP addr: {bp_addr_rtn_get_ehinfo_after_step_over}")
            if bp_addr_rtn_get_ehinfo_after_step_over != rip:
                print("Error: Expected address over rip are not same")
                import sys
                sys.exit()

            eh_clause = pykd.loadBytes(corinfo_eh_clause_addr, 24)
            eh_clause_hex = [f"0x{b:02X}" for b in eh_clause]

            detail = {
                "ftn_value": ehinfo_ftn_hex,
                "ftn_dumps": ftn_dumps,
                "eh_number": eh_number,
                "eh_clause": eh_clause_hex
            }
        # write the dump file for both compileMethod and getEhInfo
        dumpable = json.dumps(detail)
        dumpable_indented = json.dumps(detail, indent=4)
        print(dumpable)
        if flag_hit_at_compileMethod:
            file_prefix = "compileMethod"
        else:
            file_prefix = "getEhInfo"
        file_to_write = os.path.join(
            windbg_output,
            f"{file_prefix}-{dump_sequence_counter}-{hashlib.sha256(dumpable.encode()).hexdigest()}.json"
        )
        dump_sequence_counter += 1
        print(f"Writing dump at : {file_to_write}")
        with open(file_to_write, "w") as writer:
            writer.write(dumpable_indented)
        method_details.append(detail)
    except Exception as e:
        print(f"Exception: {str(e)}")

# Final dump of collected method data
print(json.dumps(method_details, indent=4))
print("\n\n\n############ Everything is done. ############\n\n\n")
