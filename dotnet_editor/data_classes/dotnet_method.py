class DotNetMethod:
    def __init__(self, md_token, full_name, method_name, parameters, is_static_method=False):
        self._md_token = md_token
        self._is_static_method = is_static_method
        self._method_name = str(method_name)
        self._parameters = parameters
        self._full_method_name = f"{full_name}.{method_name}"
        self._full_signature = f"{self._full_method_name}({', '.join(parameters)})"

    @property
    def method_name(self):
        return self._method_name

    @property
    def md_token(self):
        return self._md_token

    @property
    def parameters(self):
        return self._parameters

    @property
    def is_static_method(self):
        return self._is_static_method

    # @property
    # def full_signature(self)->str:
    #     return self._full_signature

    @property
    def full_method_name(self):
        return self._full_method_name

    def __repr__(self):
        return self._full_signature


if __name__ == '__main__':
    # 🔍 Example usage
    method = DotNetMethod("Namespace.Classname", "GetProcAddress", ["System.IntPtr", "System.String"])

    print("Method name:", method.method_name)
    print("Parameters:", method.parameters)
    print(method)
