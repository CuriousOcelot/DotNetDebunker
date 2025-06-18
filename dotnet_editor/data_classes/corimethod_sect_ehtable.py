import struct
from dataclasses import dataclass
from typing import List

from dotnet_editor.data_classes.corinfo_eh_clause import CORINFO_EH_CLAUSE


@dataclass
class CorILMethod_Sect_EHTable:
    kind: int                      # BYTE
    dataSize: int                  # BYTE (includes header + clauses)
    reserved: int                  # USHORT
    clauses: List[CORINFO_EH_CLAUSE]

    def to_bytes(self) -> bytes:
        header = struct.pack("<BBH", self.kind, self.dataSize, self.reserved)
        return header
