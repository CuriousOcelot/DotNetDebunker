import struct
from typing import Dict, List, Optional

from dotnet_editor.data_classes.corinfo_eh_clause import CORINFO_EH_CLAUSE
from dotnet_editor.utility.dn_edit_util import parse_ftn_dump
from dotnet_editor.utility.utility import hex_list_to_int_list


class EhClause:

    def __init__(self, data: Dict, exec_seq: int):
        self.exec_seq: int = exec_seq
        self._data = data

        self._ftn_value_hex = self._data["ftn_value"]

        self._ftn_dump_raw = self._data["ftn_dumps"]
        self._ftn_dump_json = parse_ftn_dump(self._ftn_dump_raw)
        self._method_token = int(self._ftn_dump_json['mdToken'], 16)

        if "Method Name" in self._ftn_dump_json:
            self._method_name: Optional[str, None] = self._ftn_dump_json["Method Name"]
        else:
            self._method_name: Optional[str, None] = None

        self._eh_number = self._data["eh_number"]
        self._eh_clause_hex = self._data["eh_clause"]

        self._ftn_value = hex_list_to_int_list(self._ftn_value_hex)
        self._eh_clause: List[int] = hex_list_to_int_list(self._eh_clause_hex)
        self._corinfo_eh_clause = CORINFO_EH_CLAUSE(*struct.unpack("<6I", bytearray(self._eh_clause)))

    @property
    def method_token(self):
        return self._method_token

    @property
    def method_name(self):
        return self._method_name

    @property
    def method_token_hex(self):
        return f"0x{self.method_token:08X}"

    @property
    def eh_number(self):
        return self._eh_number

    @property
    def eh_clause(self) -> List[int]:
        return self._eh_clause

    @property
    def eh_clause_unique_token(self):
        return self.method_token, self._eh_number

    def corinfo_eh_clause(self) -> CORINFO_EH_CLAUSE:
        return self._corinfo_eh_clause
