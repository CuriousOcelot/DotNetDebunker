from dataclasses import dataclass

from dotnet_editor.data_classes.dotnet_method import DotNetMethod


@dataclass
class MethodDefInfo:
    token: int
    prva_addr: int
    method_name: str
    method_il_code_addr: int
    method_il_code_size: int
    rva_duplicated: bool
    method_table_addr:int
    dotnet_method: DotNetMethod
