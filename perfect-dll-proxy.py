import pefile
import argparse
import os
import sys
"""
References:
- https://nibblestew.blogspot.com/2019/05/
- https://googleprojectzero.blogspot.com/2016/02/the-definitive-guide-on-win32-to-nt.html
- https://learn.microsoft.com/en-us/cpp/build/reference/export-exports-a-function
- https://devblogs.microsoft.com/oldnewthing/20121116-00/?p=6073
- https://medium.com/@lsecqt/weaponizing-dll-hijacking-via-dll-proxying-3983a8249de0
- https://book.hacktricks.xyz/windows-hardening/windows-local-privilege-escalation/dll-hijacking
- https://www.ired.team/offensive-security/persistence/dll-proxying-for-persistence
- https://github.com/Flangvik/SharpDllProxy
- https://github.com/hfiref0x/WinObjEx64
"""
def main():
    # Parse arguments
    parser = argparse.ArgumentParser(description="Generate a proxy DLL")
    parser.add_argument("dll", help="Path to the DLL to generate a proxy for")
    parser.add_argument("--output", "-o", help="Generated C++ proxy file to write to")
    parser.add_argument("--force-ordinals", "-v", action="store_true", help="Force matching ordinals")
    args = parser.parse_args()
    dll: str = args.dll
    output: str = args.output
    basename = os.path.basename(dll)
    if output is None:
        file, _ = os.path.splitext(basename)
        output = f"{file}.cpp"
    # Use the system directory if the DLL is not found
    if not os.path.exists(dll) and not os.path.isabs(dll):
        dll = os.path.join(os.environ["SystemRoot"], "System32", dll)
    if not os.path.exists(dll):
        print(f"File not found: {dll}")
        sys.exit(1)
    # Enumerate the exports
    pe = pefile.PE(dll)
    regular_exports = []
    com_exports = []
    ordinal_exports = []
    
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        ordinal = exp.ordinal
        if exp.name is None:
            # Handle ordinal-only exports
            ordinal_exports.append((f"__proxy{ordinal}", ordinal))
        else:
            name = exp.name.decode()
            # Check if this is a COM export that should be PRIVATE
            if name in {
                "DllCanUnloadNow",
                "DllGetClassObject",
                "DllInstall",
                "DllRegisterServer",
                "DllUnregisterServer",
            }:
                com_exports.append(name)
            else:
                regular_exports.append(name)

    # Generate the proxy
    with open(output, "w") as f:
        f.write(f"#include <Windows.h>\n\n")
        
        # Build the macro definitions in one chunk
        macros = []
        if regular_exports:
            macros.append(f'#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}." func')
        if com_exports:
            macros.append(f'#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}." func ",PRIVATE"')
        if ordinal_exports:
            macros.append(f'#define MAKE_EXPORT_ORDINAL(func, ord) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\System32\\\\{basename}.#" #ord ",@" #ord ",NONAME"')
        
        # 32-bit versions
        macros_32 = []
        if regular_exports:
            macros_32.append(f'#define MAKE_EXPORT(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}." func')
        if com_exports:
            macros_32.append(f'#define MAKE_EXPORT_PRIVATE(func) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}." func ",PRIVATE"')
        if ordinal_exports:
            macros_32.append(f'#define MAKE_EXPORT_ORDINAL(func, ord) "/EXPORT:" func "=\\\\\\\\.\\\\GLOBALROOT\\\\SystemRoot\\\\SysWOW64\\\\{basename}.#" #ord ",@" #ord ",NONAME"')
        
        # Output macros only if we have any
        if macros:
            f.write("#ifdef _WIN64\n")
            for macro in macros:
                f.write(f"{macro}\n")
            f.write("#else\n")
            for macro in macros_32:
                f.write(f"{macro}\n")
            f.write("#endif // _WIN64\n\n")
        
        # Regular exports
        for export_name in regular_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT(\"{export_name}\"))\n")
        
        # COM exports (PRIVATE)
        for export_name in com_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_PRIVATE(\"{export_name}\"))\n")
        
        # Ordinal-only exports
        for export_name, ordinal in ordinal_exports:
            f.write(f"#pragma comment(linker, MAKE_EXPORT_ORDINAL(\"{export_name}\", {ordinal}))\n")
        f.write("""
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
""")

if __name__ == "__main__":
    main()