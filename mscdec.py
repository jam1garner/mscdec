from msc import *
import ast2str as c_ast
from disasm import disasm as mscsb_disasm
from disasm import Label

class DecompilerError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

FLOAT_VAR_COMMANDS = [0x14, 0x15, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45]
INT_VAR_COMMANDS = [0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24]
VAR_COMMANDS = INT_VAR_COMMANDS + FLOAT_VAR_COMMANDS
BINARY_OPERATIONS = {
    0xe  : "+",
    0xf  : "-",
    0x10 : "*",
    0x11 : "/",
    0x12 : "%",
    0x16 : "&",
    0x17 : "|",
    0x19 : "^",
    0x1a : "<<",
    0x1b : ">>",
    0x25 : "==",
    0x26 : "!=",
    0x28 : "<",
    0x29 : ">",
    0x2a : ">=",
    0x3a : "+",
    0x3b : "-",
    0x3c : "*",
    0x3d : "/",
    0x46 : "==",
    0x47 : "!=",
    0x48 : "<",
    0x49 : "<=",
    0x4a : ">",
    0x4b : ">="
}

UNARY_OPERATIONS = {
    0x13 : "-",
    0x14 : "++",
    0x15 : "--",
    0x18 : "~",
    0x2b : "!",
    0x3e : "-",
    0x3f : "++",
    0x40 : "--"
}

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

def getArgs(argc):
    global currentFunc, index

    other = []
    args = []
    while len(args) < argc:
        index -= 1 
        d = decompileCmd(currentFunc[index])
        if currentFunc[index].pushBit:
            args.append(d)
        else:
            other.append(d)
    return other, args

def decompileCmd(cmd):
    global currentFunc, index, localVars, globalVars

    # TODO: Properly recognize labels as control flow
    if type(cmd) == Label:
        return None
    if type(cmd) == Command:
        c = cmd.command
        if c in [0x0, 0x1, 0x2, 0x3]:
            return None
        elif c in [0x4, 0x5]:
            pass
        elif c in [0x6, 0x8]:
            other, args = getArgs(1)
            return other + [c_ast.Return(args[0])]
        elif c in [0x7, 0x9]:
            return c_ast.Return()
        elif c in [0xA, 0xD]:
            return c_ast.Constant(cmd.parameters[0])
        elif c == 0xB:
            if cmd.parameters[0] == 0:
                return localVars[cmd.parameters[1]]
            else:
                return globalVars[cmd.parameters[1]]
        elif c in [0xe, 0xf, 0x10, 0x11, 0x12, 0x16, 0x17, 0x19, 0x1a, 0x1b, 0x25, 0x26, 0x28, 0x29, 0x2a, 0x3a, 0x3b, 0x3c, 0x3d, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b]:
            other, args = getArgs(2)
            return other + [c_ast.BinaryOp(BINARY_OPERATIONS[c], args[0], args[1])]
        elif c in [0x13, 0x18, 0x2b, 0x3e]:
            other, args = getArgs(1)
            return other + [c_ast.UnaryOp(UNARY_OPERATIONS[c], args[0])]
        elif c in [0x14, 0x15, 0x3f, 0x40]:
            if cmd.parameters[0] == 0:
                return c_ast.UnaryOp(UNARY_OPERATIONS[c], localVars[cmd.parameters[1]])
            else:
                return c_ast.UnaryOp(UNARY_OPERATIONS[c], globalVars[cmd.parameters[1]])

def decompileFunc(func, s):
    global currentFunc, index
    currentFunc = func
    index = len(func) - 1
    insertPos = len(s)
    while index >= 0:
        decompiledCmd = decompileCmd(func[index])
        if decompileCmd:
            if type(decompiledCmd) == list:
                for i in decompileCmd[::-1]:
                    s.insert(insertPos, i)
            else:
                s.insert(insertPos, decompiledCmd)
        index -= 1

def decompile(func):
    global localVars

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
    decompileFunc(func, s)

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

    mscFile = mscsb_disasm("captain.mscsb")
    
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