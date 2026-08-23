#!/usr/bin/env python3
import os
import argparse
import pyghidra

pyghidra.start("-Xmx4g")

import jpype
from java.io import File
from ghidra.program.model.data import FileDataTypeManager, DataTypeManager
from ghidra.app.util.cparser.C import CParserUtils
from ghidra.util.task import TaskMonitor

def create_win_stubs(output_dir: str) -> str:
    """Creates an expanded temporary Windows type stub header to resolve missing primitives and pointers."""
    stubs_path = os.path.join(output_dir, "win_stubs.h")
    stubs_content = """
#ifndef WIN_STUBS_H
#define WIN_STUBS_H

typedef unsigned long ULONG;
typedef ULONG *PULONG;
typedef ULONG *LPULONG;
typedef long LONG;
typedef LONG *PLONG;
typedef unsigned short USHORT;
typedef USHORT *PUSHORT;
typedef unsigned long DWORD;
typedef DWORD *PDWORD;
typedef DWORD *LPDWORD;
typedef int BOOL;
typedef void *HANDLE;
typedef void *LPVOID;
typedef const void *LPCVOID;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef unsigned short *LPWSTR;
typedef const unsigned short *LPCWSTR;
typedef long HRESULT;
typedef unsigned char BYTE;
typedef BYTE *PBYTE;
typedef BYTE *LPBYTE;
typedef unsigned short WORD;
typedef WORD *PWORD;
typedef int INT;
typedef unsigned int UINT;
typedef void VOID;

#endif
"""
    with open(stubs_path, "w", encoding="utf-8") as f:
        f.write(stubs_content.strip())
    return stubs_path

def build_gdt(header_path: str, output_dir: str, compiler_args: list):
    os.makedirs(output_dir, exist_ok=True)
    base_name = os.path.basename(header_path)
    name_without_ext = os.path.splitext(base_name)[0]
    gdt_filename = f"{name_without_ext}.gdt"
    gdt_path = os.path.join(output_dir, gdt_filename)
    
    print(f"Initializing GDT Archive: {gdt_path}")
    gdt_file = File(gdt_path)
    
    if gdt_file.exists():
        print(f"Removing existing archive at {gdt_path}")
        gdt_file.delete()

    # Create an empty FileDataTypeManager for the output archive
    dt_mgr = FileDataTypeManager.createFileArchive(gdt_file)
    # Generate Windows primitive type stubs
    stubs_path = create_win_stubs(output_dir)
    # Pass both the stubs and the target header file to the parser
    open_dtmgrs = jpype.JArray(DataTypeManager)(0)
    filenames = jpype.JArray(jpype.JString)([stubs_path, header_path])
    
    # Define base parsing macros and strip out uppercase/lowercase calling conventions & modifiers
    flags = [
        "-D_WINDOWS", 
        "-D_X86_", 
        "-DFAR=", 
        "-DNEAR=", 
        "-DPASCAL=", 
        "-DWINAPI=", 
        "-DCALLBACK=", 
        "-DAPIENTRY=",
        "-D__far=", 
        "-D__near=", 
        "-D__cdecl=", 
        "-D__stdcall=", 
        "-D__pascal=", 
        "-D__fastcall="
    ]
    if compiler_args:
        flags.extend(compiler_args)
    
    parser_args = jpype.JArray(jpype.JString)(flags)

    try:
        print(f"Parsing stubs and {header_path}...")
        
        # Execute the C Parser
        CParserUtils.parseHeaderFiles(
            open_dtmgrs, 
            filenames, 
            parser_args, 
            dt_mgr, 
            TaskMonitor.DUMMY
        )
        
        dt_mgr.save()
        type_count = dt_mgr.getDataTypeCount(True)
        
        print(f"Success: Generated GDT with {type_count} data types.")
        print(f"The GDT file is located at: {gdt_path}")
        
    except Exception as e:
        print(f"Parsing failed: {e}")
    finally:
        dt_mgr.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Headless C Header to GDT Generator")
    parser.add_argument("-i", "--input", required=True, help="Path to input .h file")
    parser.add_argument("-d", "--dir", default="gdt_archives", help="Directory to save GDTs (default: ./gdt_archives)")
    parser.add_argument("-a", "--args", nargs="*", default=[], help="Additional C parser args (e.g., -DNAME)")
    
    args = parser.parse_args()
    
    in_path = os.path.abspath(args.input)
    out_dir = os.path.abspath(args.dir)
    
    if not os.path.exists(in_path):
        print(f"Error: Input file {in_path} not found.")
        exit(1)
        
    build_gdt(in_path, out_dir, args.args)