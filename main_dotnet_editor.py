import os.path
import sys
from typing import Tuple, Dict

import qprompt

from dotnet_editor.captured_methods import CaptureMethods, MethodDetail
from dotnet_editor.helper.assembly_analyzer import AssemblyAnalyzer
from dotnet_editor.helper.pe_reader import PEModel
from dotnet_editor.utility.arg_parser_helper import ArgParserHelper
from dotnet_editor.utility.dn_edit_util import modify_method
from dotnet_editor.utility.logger_util_no_line_num import LogFormat
from dotnet_editor.utility.utility import info_logging_with_no_line_num, sha256sum, \
    sha256sum_bytes, int_to_hex, int_list_to_hex_list, error_logging_with_no_line_num

if __name__ == '__main__':
    arg_parser_helper = ArgParserHelper.parse_args()

    flag_force_new_section = arg_parser_helper.flag_force_new_section
    flag_new_sec_auto_sizing = arg_parser_helper.new_sec_auto_sizing
    flag_test_mode = arg_parser_helper.flag_test_mode
    flag_skip_qprompt = arg_parser_helper.flag_skip_qprompt
    file_path = arg_parser_helper.input_file_path
    output_file_path = arg_parser_helper.output_file_path
    windbg_output = arg_parser_helper.windebug_output
    folder_name = arg_parser_helper.folder_name

    # print(f"flag_force_new_section = {flag_force_new_section}")
    # print(f"flag_new_sec_auto_sizing = {flag_new_sec_auto_sizing}")
    # print(f"flag_test_mode = {flag_test_mode}")
    # print(f"flag_skip_qprompt = {flag_skip_qprompt}")
    # print(f"file_path = {file_path}")
    # print(f"output_file_path = {output_file_path}")
    # print(f"windbg_output = {windbg_output}")

    if not flag_skip_qprompt and not qprompt.ask_yesno(f"Edit the file: {file_path}"):
        sys.exit(1)
    # load the dll module
    pe_file = PEModel.open_packed_file(file_path)
    assembly_analyzer: AssemblyAnalyzer = AssemblyAnalyzer(pe_file, flag_new_sec_auto_sizing)
    assembly_analyzer.analyze()

    captured_methods = CaptureMethods(file_path, windbg_output, folder_name)
    captured_methods_dict: Dict[Tuple[int, str], MethodDetail] = captured_methods.method_details
    eh_clause_details = captured_methods.eh_clause_details

    captured_method_detail: MethodDetail
    for (token, method_full_name), captured_method_detail in captured_methods_dict.items():
        if not (token, method_full_name) in assembly_analyzer.method_map:
            error_logging_with_no_line_num(f"\t[*] Token: {int_to_hex(token)} \"{method_full_name}\" [Not analyzed]", )
            continue
        analyzed_method = assembly_analyzer.method_map[(token, method_full_name)]
        info_logging_with_no_line_num("\n")
        info_logging_with_no_line_num(f"\t[*] Token: {int_to_hex(token)}", )
        info_logging_with_no_line_num(f"\t[*] Name: {analyzed_method.dotnet_method.full_method_name}", )
        info_logging_with_no_line_num(
            f"\t[*] info->locals.pSig : {' '.join(int_list_to_hex_list(captured_method_detail.psig))}")

        modify_method(token, method_full_name, assembly_analyzer, analyzed_method, captured_method_detail,
                      eh_clause_details,
                      flag_force_new_section)

    if not flag_test_mode:  # Test mode will not write to output
        parent_output_path = os.path.basename(os.path.dirname(output_file_path))
        if parent_output_path.lower() == "test_unpacked_binary":
            raise Exception("Please dont write in test_unpacked_binary")
        with open(output_file_path, "wb") as output_file:
            output_file.write(assembly_analyzer.get_whole_data(as_copy=True))
        info_logging_with_no_line_num(f"Wrote at: {output_file_path}", extra=LogFormat.BLUE_UNDERLINE)

    """
    Actual extraction part code end at above line
    """

    original_sha256sum = sha256sum(file_path)
    output_sha256sum = sha256sum_bytes(assembly_analyzer.get_whole_data(as_copy=True))

    info_logging_with_no_line_num(f"Original sha256sum: {original_sha256sum}")
    info_logging_with_no_line_num(f"Output sha256sum: {output_sha256sum}")
    info_logging_with_no_line_num(f"Filename: {file_path}")

    flag_test_successfull_code = 100
    if flag_test_mode:
        prestore_out_checksum = sha256sum(output_file_path)
        if output_sha256sum == prestore_out_checksum:
            info_logging_with_no_line_num("Successfully unpacked", extra=LogFormat.BLUE_UNDERLINE)
            flag_test_successfull_code = 200
        else:
            error_logging_with_no_line_num(
                f"Unpack failed: expected > {prestore_out_checksum} | got >{output_sha256sum}")
            flag_test_successfull_code = 404

    if arg_parser_helper.flag_no_argument_passed:
        arg_parser_helper.parser.print_help()

    if flag_test_mode:
        sys.exit(flag_test_successfull_code)
