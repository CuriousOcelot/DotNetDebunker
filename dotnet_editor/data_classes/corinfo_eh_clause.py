import struct
from dataclasses import dataclass

COR_ILEXCEPTION_CLAUSE_FILTER = 0x0001


@dataclass
class CORINFO_EH_CLAUSE:
    Flags: int
    TryOffset: int
    TryLength: int
    HandlerOffset: int
    HandlerLength: int
    ClassToken: int

    # FilterOffset: Optional[int]

    # The small form of the exception clause should be used whenever the code sizes for the try block and
    # the handler code are both smaller than 256 bytes and both their offsets are smaller than 65536. The
    # format for a small exception clause is as follows
    @property
    def is_filter(self) -> bool:
        return (self.Flags & COR_ILEXCEPTION_CLAUSE_FILTER) != 0

    def can_be_tiny(self) -> bool:
        return (
                not self.is_filter and
                self.TryOffset <= 0xFFFF and
                self.TryLength <= 0xFF and
                self.HandlerOffset <= 0xFFFF and
                self.HandlerLength <= 0xFF
        )



    def to_tiny_bytes(self) -> bytes:
        clause_record = struct.pack("<HHBHBI",
                                    self.Flags,
                                    self.TryOffset,
                                    self.TryLength,
                                    self.HandlerOffset,
                                    self.HandlerLength,
                                    self.ClassToken)

        return clause_record

    def to_fat_bytes(self) -> bytes:
        # Format: Flags (4), TryOffset (4), TryLength (4), HandlerOffset (4), HandlerLength (4), ClassToken (4)
        clause_record = struct.pack("<IIIIII",
                                    self.Flags,
                                    self.TryOffset,
                                    self.TryLength,
                                    self.HandlerOffset,
                                    self.HandlerLength,
                                    self.ClassToken)
        return clause_record
