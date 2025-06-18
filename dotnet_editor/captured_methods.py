import json
import logging
import os
from typing import Dict, Tuple

from dotnet_editor.eh_clause import EhClause
from dotnet_editor.method_detail import MethodDetail
from dotnet_editor.utility.logger_util import getlogger

logger = getlogger(__name__, logging.DEBUG)


class CaptureMethods:
    def __init__(self, file_path, windbg_captured_dir, folder_name):
        self._file_path = file_path
        self._captured_path = str(os.path.join(windbg_captured_dir, folder_name))
        files = [f for f in os.listdir(self._captured_path) if os.path.isfile(os.path.join(self._captured_path, f))]
        self._method_details: Dict[Tuple[int, str], MethodDetail] = {}
        for file in files:
            base_name = os.path.basename(file)
            if not base_name.startswith("compileMethod-"): continue
            if not base_name.endswith(".json"): continue
            with open(os.path.join(self._captured_path, file), 'rb') as f:
                execution_seq = int(base_name.split("-")[1])
                json_data = json.load(f)
                # f.seek(0)
                # print(f.read().decode("utf-8"))
                method_detail = MethodDetail(json_data, execution_seq)
                flag_add = False
                if (method_detail.method_token, method_detail.psig_sha1_sum) in self._method_details:
                    print(f"Method: {method_detail.method_token_hex} already existd")
                    prev_value = self._method_details[method_detail.method_token]
                    if method_detail.il_codes_size > prev_value.il_codes_size:
                        flag_add = True
                else:
                    flag_add = True

                if flag_add:
                    self._method_details[(method_detail.method_token, method_detail.method_full_name)] = method_detail
                    logger.info(
                        f"\n\tAdding captured method:{method_detail.method_token_hex}\n"
                        f"\tILcode_size:{method_detail.il_codes_size_hex}\n"
                        f"\tIlcode: {' '.join([f'{i:02X}' for i in method_detail.il_codes])}"
                    )
        self._method_details = dict(sorted(self._method_details.items(), key=lambda x: x[1].exec_seq))

        self._eh_clause_details: Dict[(int, int):EhClause] = {}
        for file in files:
            base_name = os.path.basename(file)
            if not base_name.startswith("getEhInfo-"): continue
            if not base_name.endswith(".json"): continue
            with open(os.path.join(self._captured_path, file), 'rb') as f:
                execution_seq = int(base_name.split("-")[1])
                json_data = json.load(f)
                eh_clause = EhClause(json_data, execution_seq)
                self._eh_clause_details[eh_clause.eh_clause_unique_token] = eh_clause
                logger.info(
                    f"\n\tAdding EH clause for {eh_clause.method_token_hex}\n"
                    f"\tEH number: {eh_clause.eh_number}\n"
                    f"\tEh clause: {' '.join([f'{i:02X}' for i in eh_clause.eh_clause])}"
                )
        self._eh_clause_details = dict(sorted(self._eh_clause_details.items(), key=lambda x: x[1].exec_seq))

    @property
    def method_details(self) -> Dict[Tuple[int, str], MethodDetail]:
        return self._method_details

    @property
    def eh_clause_details(self):
        return self._eh_clause_details
