#!/usr/bin/env python3
"""
ast_patcher.py
--------------
Parses C source code using pycparser to detect functions whose return values
are assigned to typed variables, but are declared as 'void' in LLM_globals.h.
Proactively updates LLM_globals.h before compilation begins.
Also strips Ghidra cast artifacts and simplifies pointer arithmetic.
"""
from database.symbol_db import SymbolDB
import re
import os
from pycparser import c_parser, c_ast, c_generator


def sanitize_code_for_pycparser(c_code):
    """Strips compiler attributes that pycparser cannot handle.
    Note: Ghidra specifiers are preserved here and handled via typedefs 
    to prevent destroying memory size representations in the final output."""
    clean = re.sub(r'\b(__stdcall|__cdecl|__fastcall|__thiscall|__declspec\([^)]*\))\b', '', c_code)
    return clean


class AssignmentVisitor(c_ast.NodeVisitor):
    def __init__(self):
        self.function_calls = []
        self.local_vars = {}

    def visit_Decl(self, node):
        if isinstance(node.type, c_ast.TypeDecl):
            type_name = " ".join(node.type.type.names)
            self.local_vars[node.name] = type_name
        elif isinstance(node.type, c_ast.PtrDecl):
            if hasattr(node.type.type, 'type') and hasattr(node.type.type.type, 'names'):
                type_name = " ".join(node.type.type.type.names) + " *"
                self.local_vars[node.name] = type_name
            elif hasattr(node.type.type, 'names'):
                type_name = " ".join(node.type.type.names) + " *"
                self.local_vars[node.name] = type_name

    def visit_Assignment(self, node):
        rval = node.rvalue
        while isinstance(rval, c_ast.Cast):
            rval = rval.expr

        if isinstance(rval, c_ast.FuncCall):
            if isinstance(rval.name, c_ast.ID):
                func_name = rval.name.name
                
                if isinstance(node.lvalue, c_ast.ID):
                    var_name = node.lvalue.name
                    var_type = self.local_vars.get(var_name, "unknown")
                    
                    self.function_calls.append({
                        "func_name": func_name,
                        "assigned_var": var_name,
                        "required_return_type": var_type
                    })
        
        self.generic_visit(node)


def analyze_ast_types(c_code):
    # Temporarily remove includes so pycparser doesn't trip on missing system headers
    code_no_includes = re.sub(r'#include\s*[<"].*?[>"]', '', c_code)
    clean_code = sanitize_code_for_pycparser(code_no_includes)
    
    # Add Ghidra types so the AST parser can interpret them
    fake_typedefs = (
        "typedef int HANDLE; typedef int LPWSTR; typedef int LPVOID; "
        "typedef int uintptr_t; typedef int uint8_t; typedef int DWORD; "
        "typedef int BOOL; typedef int BYTE; typedef int WORD; typedef int uint;\n"
        "typedef int undefined; typedef int undefined1; typedef int undefined2; "
        "typedef int undefined4; typedef int undefined8;\n"
    )
    
    parser = c_parser.CParser()
    try:
        ast = parser.parse(fake_typedefs + clean_code)
        visitor = AssignmentVisitor()
        visitor.visit(ast)
        return visitor.function_calls
    except Exception as e:
        return []


def proactive_header_patch(header_path, ast_analysis):
    if not ast_analysis:
        return False

    db = SymbolDB()
    modified = False

    for item in ast_analysis:
        func_name = item["func_name"]
        new_type = item["required_return_type"]
        
        if new_type == "unknown":
            continue

        db.update_function_return_type(func_name, new_type)
        print(f"[AST Injection] Proactively updated '{func_name}' return type in DB -> {new_type}")
        modified = True

    if modified:
        db.export_header(header_path)
        return True
    return False


# --- NEW: AST Code Mutator and Cleaner ---

class CodeCleaner:
    def clean_node(self, node):
        """Recursively unwraps Casts and converts *(ptr + offset) into ptr[offset]."""
        for attr_name in getattr(node, '__slots__', []):
            attr = getattr(node, attr_name)
            if attr is None:
                continue
                
            if isinstance(attr, list):
                for i, child in enumerate(attr):
                    if isinstance(child, c_ast.Node):
                        self.clean_node(child)
                        
                        if isinstance(child, c_ast.Cast):
                            attr[i] = child.expr
                        elif isinstance(child, c_ast.UnaryOp) and child.op == '*':
                            # Convert *(ptr + x) -> ptr[x]
                            if isinstance(child.expr, c_ast.BinaryOp) and child.expr.op == '+':
                                attr[i] = c_ast.ArrayRef(name=child.expr.left, subscript=child.expr.right)
                                
            elif isinstance(attr, c_ast.Node):
                self.clean_node(attr)
                
                if isinstance(attr, c_ast.Cast):
                    setattr(node, attr_name, attr.expr)
                elif isinstance(attr, c_ast.UnaryOp) and attr.op == '*':
                    if isinstance(attr.expr, c_ast.BinaryOp) and attr.expr.op == '+':
                        setattr(node, attr_name, c_ast.ArrayRef(name=attr.expr.left, subscript=attr.expr.right))


def clean_decompiled_code(c_code):
    """Parses code, strips casts, simplifies pointers, and returns regenerated C string."""
    preprocessor_lines = []
    body_lines = []
    
    # 1. Protect preprocessor directives
    for line in c_code.split('\n'):
        if line.strip().startswith('#'):
            preprocessor_lines.append(line)
        else:
            body_lines.append(line)

    body_code = '\n'.join(body_lines)
    clean_body = sanitize_code_for_pycparser(body_code)

    # 2. Add Ghidra types so the AST parser can interpret them without crashing
    fake_typedefs = (
        "typedef int HANDLE; typedef int LPWSTR; typedef int LPVOID; "
        "typedef int uintptr_t; typedef int uint8_t; typedef int DWORD; "
        "typedef int BOOL; typedef int BYTE; typedef int WORD; typedef int uint;\n"
        "typedef int undefined; typedef int undefined1; typedef int undefined2; "
        "typedef int undefined4; typedef int undefined8;\n"
    )

    parser = c_parser.CParser()
    try:
        ast = parser.parse(fake_typedefs + clean_body)
    except Exception as e:
        print(f"[AST Cleaner] Skipping cast cleanup due to parse error: {e}")
        return c_code

    # 3. Strip ALL fake typedefs (including Ghidra types) so they aren't written to the clean code
    typedef_names = [
        'HANDLE', 'LPWSTR', 'LPVOID', 'uintptr_t', 'uint8_t', 'DWORD', 
        'BOOL', 'BYTE', 'WORD', 'uint',
        'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8'
    ]
    if hasattr(ast, 'ext'):
        ast.ext = [n for n in ast.ext if not (isinstance(n, c_ast.Typedef) and n.name in typedef_names)]

    # 4. Mutate the AST to remove casts and simplify pointers
    cleaner = CodeCleaner()
    cleaner.clean_node(ast)

    # 5. Regenerate code
    generator = c_generator.CGenerator()
    regenerated_code = generator.visit(ast)

    # 6. Recombine includes with clean body
    return '\n'.join(preprocessor_lines) + '\n\n' + regenerated_code