from dataclasses import dataclass
import struct


@dataclass
class CorILMethod_FatFormat:
    flags: int  # USHORT (2 bytes)
    maxStack: int  # USHORT (2 bytes)
    codeSize: int  # UINT (4 bytes)
    localVarSigTok: int  # UINT (4 bytes)

    def to_bytes(self) -> bytes:
        return struct.pack("<HHII", self.flags, self.maxStack, self.codeSize, self.localVarSigTok)
