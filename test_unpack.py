import os.path
import subprocess
import sys
from typing import List

from config import RESOURCE_PATH, PROJECT_PATH
from dotnet_editor.utility.logger_util_no_line_num import LogFormat
from dotnet_editor.utility.utility import info_logging_with_no_line_num, error_logging_with_no_line_num

"""
usage: main_dotnet_editor.py [-h] [-i INPUT] [-o OUTPUT] [-w WINDEBUG] [-y]
                             [-t] [-ns] [-a]

Example script with custom arguments

options:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input file path
  -o OUTPUT, --output OUTPUT
                        Output file path
  -w WINDEBUG, --windebug WINDEBUG
                        Windebug output file path
  -y, --yes             Skip prompt (assume yes)
  -t, --testmode        Enable test mode
  -ns, --new_section    Force new section
  -a, --new_sec_autosizing
                        Auto sizing new section

"""

if not 'PYCHARM_HOSTED' in os.environ:
    def console_log(msg, *args, **kwargs):
        print(msg)
    info_logging_with_no_line_num = error_logging_with_no_line_num = console_log


class TestExecutor:
    def __init__(self, input, output, windebug_folder):
        self._input = input
        self._output = output
        self._windebug_folder = windebug_folder
        self._script_path = str(os.path.join(PROJECT_PATH, "main_dotnet_editor.py"))
        pass

    def run_script(self, extra: List[str], message=""):
        args = [sys.executable, self._script_path, "-i", self._input, "-o", self._output, "-w", self._windebug_folder,
                "-y", "-t"]
        args.extend(extra)
        result = subprocess.run(args, capture_output=True, text=True)
        # print(result.stderr)
        if result.returncode == 200:
            info_logging_with_no_line_num(f"{os.path.basename(self._input)} Okey [✅] {message}",
                                          extra=LogFormat.BLUE_UNDERLINE)
            # print("Output:", result.stderr)
        elif result.returncode == 404:
            error_logging_with_no_line_num(f"{os.path.basename(self._input)} Oops [❌] {message}")
            # print("Error running script:", result.stderr)
        else:
            error_logging_with_no_line_num(
                f"{os.path.basename(self._input)} Oops [❌] [Unknown result code: {result.returncode}] {message}")


if __name__ == '__main__':
    windebug_folder = os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "windbg_output")
    packed_rsc_path = os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "test_packed_binary")
    unpacked_rsc_path = os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "test_unpacked_binary")
    newsec_unpacked_rsc_path = os.path.join(RESOURCE_PATH, "jit_hook_test_binary", "newsec_test_unpacked_binary")

    for file in os.listdir(packed_rsc_path):
        if not file.endswith(".exe"): continue
        input_full_path = os.path.join(packed_rsc_path, file)
        output_full_path = os.path.join(unpacked_rsc_path, file[:-10] + "unpacked.exe")
        test_executer = TestExecutor(input_full_path, output_full_path, windebug_folder)
        test_executer.run_script([], "")
        # test_executer.run_script(["-ns"], "")

    for file in os.listdir(packed_rsc_path):  # force new section addition
        if not file.endswith(".exe"): continue
        input_full_path = os.path.join(packed_rsc_path, file)
        output_full_path = os.path.join(newsec_unpacked_rsc_path, file[:-10] + "unpacked.exe")
        test_executer = TestExecutor(input_full_path, output_full_path, windebug_folder)
        test_executer.run_script(["-ns"], "[force add new section.]")
        # test_executer.run_script([], "[force add new section.]")
