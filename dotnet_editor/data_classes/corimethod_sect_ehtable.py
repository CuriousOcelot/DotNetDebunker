import abc
import logging
from dataclasses import dataclass
from typing import List

from dotnet_editor.data_classes.corinfo_eh_clause import CORINFO_EH_CLAUSE
from dotnet_editor.utility.logger_util import getlogger

logger = getlogger(__name__, logging.DEBUG)


@dataclass
class CorILMethod_Sect_EHTable:
    eh_count: int
    pass

    @abc.abstractmethod
    def to_bytes(self) -> bytes:
        raise NotImplementedError('Method not implemented')


@dataclass
class CorILMethod_Sect_EHTable_Tiny(CorILMethod_Sect_EHTable):
    clauses: List[CORINFO_EH_CLAUSE]

    def to_bytes(self) -> bytes:
        max_eh_count = (0xFF - 4) // 12
        if self.eh_count > max_eh_count:
            logger.error("Too many exception handlers")
            self.eh_count = max_eh_count

        ehtable_detail = ((self.eh_count * 12 + 4) << 8) | 1
        byte_data = ehtable_detail.to_bytes(4, byteorder='little', signed=False)
        return byte_data


@dataclass
class CorILMethod_Sect_EHTable_Fat(CorILMethod_Sect_EHTable):
    clauses: List[CORINFO_EH_CLAUSE]

    def to_bytes(self) -> bytes:
        max_eh_count = (0x00FFFFFF - 4) // 24
        if self.eh_count > max_eh_count:
            logger.error("Too many exception handlers")
            self.eh_count = max_eh_count

        ehtable_detail = ((self.eh_count * 24 + 4) << 8) | 0x41
        byte_data = ehtable_detail.to_bytes(4, byteorder='little', signed=False)
        return byte_data
