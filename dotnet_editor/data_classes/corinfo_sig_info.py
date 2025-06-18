import struct
from dataclasses import dataclass


@dataclass
class CORINFO_SIG_INFO:
    callConv: int  # void*
    retTypeClass: int  # void*
    retTypeSigClass: int  # void*
    retType_flags_numArgs: int  # uint64_t
    sigInst0: int  # uint64_t
    sigInst1: int  # uint64_t
    sigInst2: int  # uint64_t
    sigInst3: int  # uint64_t
    args: int  # void*
    pSig: int  # uint8_t*
    cbSig: int  # originally uint32_t, treated as pointer
    scope: int  # void*
    token: int  # originally uint32_t, treated as pointer


CORINFO_SIG_INFO_STRUCT_FOEMATE = struct.Struct('<' + (
        'Q' * 3 +  # callConv, retTypeClass, retTypeSigClass (3 x void* => 3 x Q)
        'Q' * 5 +  # retType_flags_numArgs, sigInst0..sigInst3 (4 x uint64_t)
        'Q' * 2 +  # args, pSig (void*, uint8_t*)
        'Q' * 3  # cbSig (uint32_t*), scope (void*), token (uint32_t*)
))


def get_corinfo_sig_info(data: bytes)->CORINFO_SIG_INFO:
    fields = CORINFO_SIG_INFO_STRUCT_FOEMATE.unpack(data)
    return CORINFO_SIG_INFO(*fields)
