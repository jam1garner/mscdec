from msc import *
import ast2str as c_ast
from disasm import disasm

class DecompilerError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

FLOAT_VAR_COMMANDS = [0x14, 0x15, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45]
INT_VAR_COMMANDS = [0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24]
VAR_COMMANDS = INT_VAR_COMMANDS + FLOAT_VAR_COMMANDS

def getLocalVarTypes(func, varCount):
    varInt = {}
    varFloat = {}
    for cmd in func:
        if type(cmd) != Command:
            continue
        if cmd.command in VAR_COMMANDS and cmd.parameters[0] == 0:
            varNum = cmd.parameters[1]
            if cmd.command in INT_VAR_COMMANDS:
                if not varNum in varInt:
                    varInt[varNum] = 1
                else:
                    varInt[varNum] += 1
            else:
                if not varNum in varFloat:
                    varFloat[varNum] = 1
                else:
                    varFloat[varNum] += 1

    localVarTypes = ["int" for i in range(varCount)]
    for i in range(varCount):
        if i in varInt or i in varFloat:
            intCount = varInt[i] if i in varInt else 0
            floatCount = varFloat[i] if i in varFloat else 0
            if floatCount > intCount:
                localVarTypes[i] = "float"

    return localVarTypes

def decompile(func):
    f = c_ast.FuncDef("void", func.name, c_ast.DeclList(), c_ast.Statements())
    # If non-empty function that doesn't start with 0x2
    if len(func.cmds) != 0 and func.cmds[0].command != 0x2:
        raise DecompilerError("Script {} doesn't start with a begin".format(func.name))
    beginCommand = func.cmds[0]
    argc = beginCommand.parameters[0]
    varc = beginCommand.parameters[1]
    localVarTypes = getLocalVarTypes(func, varc)
    localVars = []
    localVarDecls = []
    for i in range(argc):
        f.args.append(c_ast.Decl(localVarTypes[i], "arg{}".format(i)))
        localVars.append(c_ast.ID("arg{}".format(i)))
    for i in range(varc - argc):
        localVarDecls.append(c_ast.Decl(localVarTypes[i + argc], "var{}".format(i + argc)))
        localVars.append(c_ast.ID("var{}".format(i + argc)))

    s = f.statements

    # Insert local var declarations at the beginning of the function, in order
    for i, decl in enumerate(localVarDecls):
        s.insert(i, decl)

    return f

def getGlobalVars(mscFile):
    varInt = {}
    varFloat = {}
    globalVarCount = 0
    for script in mscFile:
        for cmd in script:
            if type(cmd) != Command:
                continue
            if cmd.command in VAR_COMMANDS and cmd.parameters[0] == 1:
                varNum = cmd.parameters[1]
                if varNum > globalVarCount:
                    globalVarCount = varNum
                if cmd.command in INT_VAR_COMMANDS:
                    if not varNum in varInt:
                        varInt[varNum] = 1
                    else:
                        varInt[varNum] += 1
                else:
                    if not varNum in varFloat:
                        varFloat[varNum] = 1
                    else:
                        varFloat[varNum] += 1

    globalVarTypes = ["int" for i in range(globalVarCount)]
    for i in range(globalVarCount):
        if i in varInt or i in varFloat:
            intCount = varInt[i] if i in varInt else 0
            floatCount = varFloat[i] if i in varFloat else 0
            if floatCount > intCount:
                globalVarTypes[i] = "float"

    return [c_ast.Decl(globalVarTypes[i], "global{}".format(i)) for i in range(globalVarCount)]

def printC(globalVars, funcs, file=None):
    for decl in globalVars:
        print(str(decl) + ";", file=file)

    print(file=file)

    for func in funcs:
        print(func, file=file)
        print(file=file)

def main():
    global globalVars

    mscFile = disasm("captain.mscsb")
    
    globalVarDecls = getGlobalVars(mscFile)

    globalVars = [c_ast.ID(decl.name) for decl in globalVarDecls]
    funcs = []
    
    # Rename entrypoint function to "main"
    mscFile.getScriptAtLocation(mscFile.entryPoint).name = 'main'
    
    for script in mscFile:
        funcs.append(decompile(script))

    printC(globalVarDecls, funcs)

if __name__ == "__main__":
    main()