import hashlib
from typing import Dict, List, Optional

from dotnet_editor.data_classes.corinfo_sig_info import get_corinfo_sig_info
from dotnet_editor.utility.dn_edit_util import get_local_var_sig, parse_ftn_dump
from dotnet_editor.utility.utility import hex_list_to_int_list


class MethodDetail:
    def __init__(self, data: Dict, exec_seq: int):
        self.exec_seq: int = exec_seq
        self._data = data
        self._corinfo_bytes_hex = self._data["corinfo"]
        self._corinfo_bytes = hex_list_to_int_list(self._corinfo_bytes_hex)

        self._ftn_value_hex = self._data["ftn_value"]
        self._ftn_dump_raw = self._data["ftn_dumps"]
        self._ftn_dump_json = parse_ftn_dump(self._ftn_dump_raw)
        self._method_token = int(self._ftn_dump_json['mdToken'], 16)
        if "Method Name" in self._ftn_dump_json:
            mname_splted = self._ftn_dump_json["Method Name"].split("(")
            if len(mname_splted) != 2:
                raise Exception(f"Invalid method name: {mname_splted}")
            self._method_full_name: Optional[str, None] = mname_splted[0]
        else:
            self._method_full_name: Optional[str, None] = None

        self._scope_value_hex = self._data["scope_value"]
        self._il_codes_hex = self._data["il_codes"]
        self._il_code_size_hex = self._data["il_code_size"]

        self._max_stack_hex = self._data["max_stack"]
        self._eh_count_hex = self._data["eh_count"]
        self._options_hex = self._data["options"]
        self._region_kind_hex = self._data["region_kind"]
        self._args_hex = self._data["args"]
        self._locals_hex = self._data["locals"]
        self._psig_hex = self._data["psig"]
        self._psig_full_hex = self._data["psig_full"]

        self._ftn_value = hex_list_to_int_list(self._ftn_value_hex)
        self._scope_value = hex_list_to_int_list(self._scope_value_hex)
        self._il_codes = hex_list_to_int_list(self._il_codes_hex)
        self._il_code_size = int(self._il_code_size_hex, 16)

        self._max_stack = int(self._max_stack_hex, 16)
        self._eh_count = int(self._eh_count_hex, 16)
        self._options = int(self._options_hex, 16)
        self._region_kind = int(self._region_kind_hex, 16)
        self._args = hex_list_to_int_list(self._args_hex)
        self._locals = hex_list_to_int_list(self._locals_hex)

        self._ftn_value = hex_list_to_int_list(self._ftn_value_hex)

        self._locals_struct = get_corinfo_sig_info(bytearray(self._locals))
        self._psig: List[int] = hex_list_to_int_list(self._psig_hex)
        self._psig_bytes = bytes(self._psig)
        self._psig_sha1 = hashlib.sha1(self._psig_bytes).hexdigest()
        self._psig_full = hex_list_to_int_list(self._psig_full_hex)
        if len(self._psig) > 0:
            calculated_psig = get_local_var_sig(self._psig_full)
            if calculated_psig != self._psig:
                raise Exception("PSIG calculation failed")

    @property
    def method_full_name(self):
        return self._method_full_name

    @property
    def corinfo_bytes_hex(self):
        return self._corinfo_bytes_hex

    @property
    def il_codes(self):
        return self._il_codes

    @property
    def il_codes_hex(self):
        return self._il_codes_hex

    @property
    def il_codes_size(self):
        return self._il_code_size

    @property
    def il_codes_size_hex(self):
        return self._il_code_size_hex

    @property
    def max_stack(self):
        return self._max_stack

    @property
    def eh_count(self):
        return self._eh_count

    @property
    def options(self):
        return self._options

    @property
    def region_kind(self):
        return self._region_kind

    @property
    def args(self):
        return self._args

    @property
    def locals(self):
        return self._locals

    @property
    def psig(self) -> List[int]:
        return self._psig

    @property
    def psig_sha1_sum(self):
        return self._psig_sha1

    @property
    def method_token(self):
        return self._method_token

    @property
    def method_token_hex(self):
        return f"0x{self._method_token:08X}"
