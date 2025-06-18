import argparse
import os.path
import sys

from config import RESOURCE_PATH
from dotnet_editor.utility.utility import error_logging_with_no_line_num


class ArgParserHelper:

    def __init__(self, parser, flag_no_argument_passed):
        self._parser = parser
        self._flag_no_argument_passed = flag_no_argument_passed
        self._flag_force_new_section = False
        self._flag_test_mode = True
        self._flag_skip_qprompt = True
        self._new_sec_auto_sizing = False
        self._input_file_path = str(
            os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "test_packed_binary", "testprog_packed.exe"))
        self._output_file_path = str(
            os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "test_unpacked_binary", "testprog_unpacked.exe"))
        self._windebug_output = str(
            os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "windbg_output"))
        self._folder_name = None

    @property
    def parser(self):
        return self._parser
    @property
    def folder_name(self):
        if self._folder_name is None:
            return os.path.splitext(os.path.basename(self._input_file_path))[0]
        else:
            return self._folder_name


    @property
    def flag_no_argument_passed(self):
        return self._flag_no_argument_passed

    @property
    def flag_force_new_section(self):
        return self._flag_force_new_section

    @property
    def new_sec_auto_sizing(self):
        return self._new_sec_auto_sizing

    @property
    def flag_test_mode(self):
        if not self._flag_test_mode:
            parent_output_path = os.path.basename(os.path.dirname(self._output_file_path))
            if parent_output_path.lower() == "test_unpacked_binary":
                error_logging_with_no_line_num("Seems like writing in 'test_unpacked_binary'-> enabled test_mode")
                return True

        return self._flag_test_mode

    @property
    def flag_skip_qprompt(self):
        return self._flag_skip_qprompt

    @property
    def input_file_path(self):
        return self._input_file_path

    @property
    def output_file_path(self):
        return self._output_file_path

    @property
    def windebug_output(self):
        return self._windebug_output

    def load_arguments(
            self,
            input_file_path,
            output_file_path,
            windebug_output,
            folder_name,
            flag_force_new_section,
            new_sec_autosizing,
            flag_test_mode,
            flag_skip_qprompt):
        if input_file_path is not None and output_file_path is None:
            self._input_file_path = input_file_path
            self._output_file_path = os.path.join(os.path.dirname(input_file_path),
                                                  f"edited_{os.path.basename(input_file_path)}")
            pass
        elif input_file_path is not None and output_file_path is not None:
            self._input_file_path = input_file_path
            self._output_file_path = output_file_path
            pass
        else:
            pass

        if windebug_output is not None:
            self._windebug_output = windebug_output

        if folder_name is not None:
            self._folder_name = folder_name

        self._flag_force_new_section = flag_force_new_section
        self._new_sec_auto_sizing = new_sec_autosizing
        self._flag_test_mode = flag_test_mode
        self._flag_skip_qprompt = flag_skip_qprompt

        pass

    @classmethod
    def parse_args(cls) -> 'ArgParserHelper':
        parser = argparse.ArgumentParser(description="Example script with custom arguments")

        parser.add_argument('-i', '--input', type=str,
                            help='Input file path')
        parser.add_argument('-o', '--output', type=str,
                            help='Output file path')
        parser.add_argument('-w', '--windebug', type=str,
                            help='Windebug output file path')
        parser.add_argument('-f', '--folder_name', type=str,
                            help='Windebug Exported folder name')
        parser.add_argument('-y', '--yes', action='store_true', default=False,
                            help='Skip prompt (assume yes)')
        parser.add_argument('-t', '--testmode', action='store_true', default=False,
                            help='Enable test mode')
        parser.add_argument('-ns', '--new_section', action='store_true', default=False,
                            help='Force new section')
        parser.add_argument('-a', '--new_sec_autosizing', action='store_true', default=False,
                            help='Auto sizing new section')

        parsed = parser.parse_args()
        if len(sys.argv) == 1:
            flag_no_argument_passed = True
        else:
            flag_no_argument_passed = False
        arg_parser_helper = cls(parser, flag_no_argument_passed)
        arg_parser_helper.load_arguments(
            parsed.input,
            parsed.output,
            parsed.windebug,
            parsed.folder_name,
            parsed.new_section,
            parsed.new_sec_autosizing,
            parsed.testmode,
            parsed.yes,
        )

        return arg_parser_helper


if __name__ == '__main__':
    ArgParserHelper.parse_args()
