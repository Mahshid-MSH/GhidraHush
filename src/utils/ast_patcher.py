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
    """
    Traverses the AST to record variable types and detect when function return 
    values are assigned to variables with concrete types.
    """
    def __init__(self):
        self.function_calls = []
        self.var_types = {}
        self.generator = c_generator.CGenerator()

    def _get_type_str(self, decl_node):
        """Extracts the type string from a Decl node."""
        try:
            return self.generator.visit(decl_node.type).strip()
        except Exception:
            return "unknown"

    def _get_func_name(self, func_call_node):
        """Extracts function name from a FuncCall node if it's a direct call ID."""
        if isinstance(func_call_node.name, c_ast.ID):
            return func_call_node.name.name
        return None

    def visit_Decl(self, node):
        if node.name and node.type:
            # Record local variable / global declaration type
            type_str = self._get_type_str(node)
            self.var_types[node.name] = type_str

            # Check if variable is initialized with a function call (e.g., int x = foo();)
            if isinstance(node.init, c_ast.FuncCall):
                func_name = self._get_func_name(node.init)
                if func_name:
                    self.function_calls.append({
                        "func_name": func_name,
                        "required_return_type": type_str
                    })

        self.generic_visit(node)

    def visit_Assignment(self, node):
        # Check direct assignment to a function call (e.g., x = foo();)
        if isinstance(node.rvalue, c_ast.FuncCall):
            func_name = self._get_func_name(node.rvalue)
            if func_name:
                lvalue_type = "unknown"
                if isinstance(node.lvalue, c_ast.ID):
                    lvalue_type = self.var_types.get(node.lvalue.name, "unknown")
                
                if lvalue_type != "unknown":
                    self.function_calls.append({
                        "func_name": func_name,
                        "required_return_type": lvalue_type
                    })

        self.generic_visit(node)


class CodeCleaner(c_ast.NodeVisitor):

    def visit_Assignment(self, node):
        # Catch assignments like: socketHandle = sth (where sth is int)
        # or pointer = 0x1234
        if isinstance(node.rvalue, c_ast.Constant) and node.rvalue.type == 'int':
            # Wrap the rvalue with a cast to (void*)(uintptr_t)
            uintptr_type = c_ast.TypeDecl(declname='', quals=[], type=c_ast.IdentifierType(['uintptr_t']))
            void_ptr_type = c_ast.PtrDecl(quals=[], type=c_ast.TypeDecl(declname='', quals=[], type=c_ast.IdentifierType(['void'])))
            # Cast constant to (void*)(uintptr_t)(value)
            inner_cast = c_ast.Cast(c_ast.Typename(name=None, quals=[], type=uintptr_type), node.rvalue)
            node.rvalue = c_ast.Cast(c_ast.Typename(name=None, quals=[], type=void_ptr_type), inner_cast)
            
        self.generic_visit(node)

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
        print(f"[AST Analysis Error] {e}")
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

    # 3. Strip ALL fake typedefs so they aren't written to the clean code
    typedef_names = [
        'HANDLE', 'LPWSTR', 'LPVOID', 'uintptr_t', 'uint8_t', 'DWORD', 
        'BOOL', 'BYTE', 'WORD', 'uint',
        'undefined', 'undefined1', 'undefined2', 'undefined4', 'undefined8'
    ]
    if hasattr(ast, 'ext'):
        ast.ext = [n for n in ast.ext if not (isinstance(n, c_ast.Typedef) and n.name in typedef_names)]

    # 4. Mutate the AST
    cleaner = CodeCleaner()
    cleaner.clean_node(ast)  # Step 1: Strip unwanted Ghidra casts/simplify pointers
    cleaner.visit(ast)       # Step 2: Traverse AST & wrap raw integer assignments with (void*)(uintptr_t)

    # 5. Regenerate code
    generator = c_generator.CGenerator()
    regenerated_code = generator.visit(ast)
    # 6. Recombine includes with clean body
    return '\n'.join(preprocessor_lines) + '\n\n' + regenerated_code