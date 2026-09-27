#!/usr/bin/env python3
"""
ghidra_type_resolver.py
-----------------------
Leverages PyGhidra and low-level P-code analysis to automatically resolve dynamically 
loaded APIs via `GetProcAddress`, retype their return variables with precise function 
signatures from GDTs (Ghidra Data Type Archives), and propagate those types downstream 
to internal function parameters.
"""

import pyghidra
from ghidra.program.model.pcode import PcodeOp, HighFunctionDBUtil
from ghidra.program.model.symbol import SourceType
from ghidra.program.model.data import PointerDataType, FunctionDefinition, TypeDef


def propagate_downstream_types(program, decompiler, target_funcs):
    """
    Analyzes calls made by target functions to forward resolved function pointer 
    types to internal downstream functions.
    
    Why it's here: When an API or function pointer (such as a resolved Windows API 
    or custom callback) is passed as an argument to another internal function 
    (e.g., _SendMail), this function inspects the argument data types and updates 
    the downstream function's parameter signature from generic 'undefined' to the 
    precise type.
    """
    print("\nStarting Forward Type Propagation to downstream functions...")
    tx_id = program.startTransaction("Propagate Types Downstream")
    
    try:
        for func in target_funcs:
            results = decompiler.decompileFunction(func, 60, None)
            high_func = results.getHighFunction()
            if not high_func:
                continue
            
            ops = high_func.getPcodeOps()
            while ops.hasNext():
                op = ops.next()
                if op.getOpcode() != PcodeOp.CALL:
                    continue
                    
                # Identify the target function being called
                target_addr = op.getInput(0).getAddress()
                target_func = program.getFunctionManager().getFunctionAt(target_addr)
                
                # Ignore external libraries and thunks (focus strictly on internal binary functions)
                if not target_func or target_func.isExternal() or target_func.isThunk():
                    continue
                    
                # Iterate through arguments passed in the call operation
                params = target_func.getParameters()
                
                for i in range(1, op.getNumInputs()):
                    param_idx = i - 1
                    if param_idx >= len(params):
                        break  # Function signature lacks this parameter index
                        
                    arg_vn = op.getInput(i)
                    if not arg_vn or not arg_vn.getHigh():
                        continue
                        
                    arg_dt = arg_vn.getHigh().getDataType()
                    if not arg_dt:
                        continue
                        
                    arg_dt_name = arg_dt.getName().lower()
                    
                    # If the argument type is known and the target parameter is un typed ("undefined")
                    if "undefined" not in arg_dt_name and "int" not in arg_dt_name:
                        target_param = params[param_idx]
                        param_dt_name = target_param.getDataType().getName().lower()
                        
                        if "undefined" in param_dt_name:
                            print(f"    [>] Propagating type '{arg_dt.getName()}' to '{target_func.getName()}' (Parameter {param_idx + 1})")
                            try:
                                target_param.setDataType(arg_dt, SourceType.USER_DEFINED)
                            except Exception as e:
                                print(f"Failed to update parameter: {e}")
                                
    finally:
        program.endTransaction(tx_id, True)
        print(" Propagation complete.")


def resolve_getprocaddress_types(program, decompiler):
    """
    Automates the resolution of dynamically loaded API calls via `GetProcAddress` 
    by inspecting P-code, tracing API name string arguments in memory, matching 
    them against loaded GDT archives, and retyping the resulting function pointers.
    """
    dt_mgr = program.getDataTypeManager()

    # Pre-load known APIs (FunctionDefinitions) and TypeDefs from GDTs
    known_apis = {}
    known_typedefs = {}
    all_dts = dt_mgr.getAllDataTypes()
    
    while all_dts.hasNext():
        dt = all_dts.next()
        name_lower = dt.getName().lower()
        if isinstance(dt, FunctionDefinition):
            known_apis[name_lower] = dt
        elif isinstance(dt, TypeDef):
            known_typedefs[name_lower] = dt

    print(f" Loaded {len(known_apis)} functions and {len(known_typedefs)} typedefs from DTM/GDTs.")

    symbol_table = program.getSymbolTable()
    ref_mgr = program.getReferenceManager()

    # Identify all memory addresses associated with GetProcAddress
    gpa_addresses = set()
    for s in symbol_table.getSymbols("GetProcAddress"):
        if s.getAddress():
            gpa_addresses.add(s.getAddress())
        if s.isExternal():
            ext_loc = program.getExternalManager().getExternalLocation(s)
            if ext_loc and ext_loc.getAddress():
                gpa_addresses.add(ext_loc.getAddress())

    call_instruction_addrs = set()
    for addr in gpa_addresses:
        for ref in ref_mgr.getReferencesTo(addr):
            call_instruction_addrs.add(ref.getFromAddress())

    target_funcs = set()
    for call_addr in call_instruction_addrs:
        func = program.getFunctionManager().getFunctionContaining(call_addr)
        if func:
            target_funcs.add(func)

    print(f" Spread across {len(target_funcs)} function(s).")

    tx_id = program.startTransaction("Propagate GetProcAddress Data Types via P-Code")
    try:
        for func in target_funcs:
            results = decompiler.decompileFunction(func, 60, None)
            high_func = results.getHighFunction()

            if not high_func:
                print(f"     Failed to decompile function {func.getName()}")
                continue

            # Iterate raw P-Code operations directly
            ops = high_func.getPcodeOps()
            while ops.hasNext():
                op = ops.next()
                
                if op.getOpcode() not in [PcodeOp.CALL, PcodeOp.CALLIND]:
                    continue
                    
                # Check if the instruction address belongs to our known GetProcAddress calls
                instr_addr = op.getSeqnum().getTarget()
                is_gpa = (instr_addr in call_instruction_addrs)
                
                # Fallback: Check if the target pointer resolves directly to GetProcAddress
                if not is_gpa:
                    input0 = op.getInput(0)
                    if input0 and input0.isAddress():
                        sym = symbol_table.getPrimarySymbol(input0.getAddress())
                        if sym and "GetProcAddress" in sym.getName():
                            is_gpa = True
                            
                if not is_gpa:
                    continue

                print(f"     Matched GetProcAddress call at {instr_addr} in function {func.getName()}")

                if op.getNumInputs() <= 2:
                    continue

                # Trace the API name string argument (Input 2) across varnodes/registers
                name_varnode = op.getInput(2)
                string_addr = None
                
                if name_varnode.isConstant():
                    space = program.getAddressFactory().getDefaultAddressSpace()
                    string_addr = space.getAddress(name_varnode.getOffset())
                elif name_varnode.isAddress():
                    string_addr = name_varnode.getAddress()
                elif name_varnode.isRegister() or name_varnode.isUnique():
                    # Trace back through defining operations if loaded into temporary registers
                    def_op = name_varnode.getDef()
                    if def_op:
                        if def_op.getOpcode() == PcodeOp.PTRSUB:
                            ptr_vn = def_op.getInput(1)
                            if ptr_vn.isConstant():
                                space = program.getAddressFactory().getDefaultAddressSpace()
                                string_addr = space.getAddress(ptr_vn.getOffset())
                        elif def_op.getOpcode() == PcodeOp.COPY:
                            copy_in = def_op.getInput(0)
                            if copy_in.isAddress():
                                string_addr = copy_in.getAddress()
                            elif copy_in.isConstant():
                                space = program.getAddressFactory().getDefaultAddressSpace()
                                string_addr = space.getAddress(copy_in.getOffset())

                # Read string from binary memory safely
                api_name = None
                if string_addr:
                    try:
                        mem = program.getMemory()
                        extracted_str = ""
                        offset = 0
                        while offset < 255:
                            b = mem.getByte(string_addr.add(offset)) & 0xFF
                            if b == 0:
                                break
                            extracted_str += chr(b)
                            offset += 1
                        if len(extracted_str) > 2:
                            api_name = extracted_str
                    except Exception as e:
                        print(f"         Memory read failed at {string_addr}: {e}")

                if not api_name:
                    print(f"         Could not extract valid API name for {instr_addr}.")
                    continue

                api_name = api_name.strip()
                print(f"        -> Resolved API string: '{api_name}'")

                # Match against loaded GDT function definitions and typedefs
                fn_ptr_type = None
                target_lower = api_name.lower()

                matched_dt = known_apis.get(target_lower) or known_apis.get(target_lower + 'a') or known_apis.get(target_lower + 'w')
                if matched_dt:
                    fn_ptr_type = PointerDataType(matched_dt)
                else:
                    td = known_typedefs.get(target_lower) or known_typedefs.get("lp" + target_lower) or known_typedefs.get("p" + target_lower)
                    if td:
                        fn_ptr_type = td

                if not fn_ptr_type:
                    print(f"        No matching TypeDef/FunctionDefinition found for '{api_name}' in GDTs.")
                    continue

                # Apply precise type updates directly to HighVariables
                output_vn = op.getOutput()
                if not output_vn:
                    continue

                high_var = output_vn.getHigh()
                if high_var:
                    high_sym = high_var.getSymbol()
                    if high_sym:
                        try:
                            HighFunctionDBUtil.updateDBVariable(high_sym, None, fn_ptr_type, SourceType.USER_DEFINED)
                            print(f"            Retyped target symbol '{high_sym.getName()}' to {fn_ptr_type.getName()}")
                        except Exception as e:
                            print(f"            Failed to update DB variable: {e}")
                    else:
                        try:
                            high_var.setDataType(fn_ptr_type, True)
                            print(f"            Retyped temporary variable to {fn_ptr_type.getName()} (Ephemeral)")
                        except Exception:
                            pass

    finally:
        program.endTransaction(tx_id, True)
        
    return target_funcs