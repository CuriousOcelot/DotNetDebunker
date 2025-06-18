# WinDbg Debugging Steps

WinDbg is a powerful debugger for Windows that provides deep inspection capabilities.

## 🧰 Prerequisites

- WinDbg  
- `pykd.dll` (Python extension for WinDbg)  
- Ghidra *(optional, for analyzing binaries)*

---

## ⚙️ Setup Instructions

1. Load `pykd` extension in WinDbg:  
   ```text
   .load C:\path\to\pykd.dll;
   ```

2. Set a breakpoint for `clrjit.dll` load and run:  
   ```text
   sxe ld clrjit.dll; g;
   ```

3. Load interactive Python in WinDbg:  
   ```text
   !py;
   ```

4. In interactive Python, run:  
   ```python
   run = lambda path: exec(open(path).read()); run(r"C:\path\to\windbg.py"); quit();
   ```

> You can also run everything in one line:
```text
.load C:\path\to\pykd_ext_2.0.0.25_x64\pykd.dll; sxe ld clrjit.dll; g; !py;
```

```python
run = lambda path: exec(open(path).read()); run(r"C:\path\to\windbg.py"); quit();
```

5. This will automatically break at `CILJit::compileMethod` and just before calling `getEHinfo`.  
   It will capture the arguments and results, saving them to:  
   ```
   ~/Downloads/windbg_output
   ```

6. ⚠️ Note: Breakpoint addresses are hardcoded and **may differ** between versions of `clrjit.dll`.

---

## 🧭 Finding Breakpoint Addresses

1. Load the DLL/EXE in Ghidra or a similar tool.  
2. Identify the target line/function and set a breakpoint where desired.  
3. Load the program and let the breakpoint hit.  
4. Get the address of the breakpoint in memory.  
5. Get the module base address in WinDbg using:  
   ```text
   lm m module_name
   ```
   Example:  
   ```text
   lm m clrjit
   ```

6. Calculate the offset by subtracting the module base address from the breakpoint address.

Example breakpoint command:
```text
ba e1 clrjit+0x7a6e0
```
Here, `0x7a6e0` is the calculated offset.

---

Happy debugging! 🐞
