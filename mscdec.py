from msc import *
import ast2str as c_ast
from disasm import disasm as mscsb_disasm
from disasm import Label
from disasm import ScriptRef
import operator

class DecompilerError(Exception):
    def __init__(self,*args,**kwargs):
        Exception.__init__(self,*args,**kwargs)

class Cast:
    def __init__(self, type):
        self.type = type

class FunctionCallGroup(list):
    def __init__(self, pushBit=False):
        super().__init__(self)
        self.pushBit = pushBit

FLOAT_VAR_COMMANDS = [0x14, 0x15, 0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45]
INT_VAR_COMMANDS = [0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24]
VAR_COMMANDS = INT_VAR_COMMANDS + FLOAT_VAR_COMMANDS + [0xb]
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
    0x27 : "<",
    0x28 : "<=",
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

ASSIGNMENT_OPERATIONS = {
    0x1c : "=",
    0x1d : "+=",
    0x1e : "-=",
    0x1f : "*=",
    0x20 : "/=",
    0x21 : "%=",
    0x22 : "&=",
    0x23 : "|=",
    0x24 : "^=",
    0x41 : "=",
    0x42 : "+=",
    0x43 : "-=",
    0x44 : "*=",
    0x45 : "/="
}

# Gets the local variable types for a function
# is merely an educated guess based on what commands
# reference it.
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
            elif cmd.command in FLOAT_VAR_COMMANDS:
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

# Helper function for decompileCmd which is used for recursive calls in order
# to grab arguments based on their pushbit so they can be used within the
# original command. Returns a tuple of lists, the first being commands run in between
# and the later being the arguments to use.
def getArgs(argc):
    global currentFunc, index

    other = []
    args = []
    while len(args) < argc and index >= 0:
        index -= 1 
        d = decompileCmd(currentFunc[index])
        if type(d) == list:
            other = d[:-1] + other
            d = d[-1]
        if ((type(currentFunc[index]) in [Command, FunctionCallGroup]) and currentFunc[index].pushBit) or type(currentFunc[index]) == Cast:
            args.append(d)
        else:
            other.append(d)
    return other, args

# Recursively decompile from commands to an AST, uses global variable "index" to keep track of position,
# iterating backwards through the function in order to assign arguments to the things that use them.
def decompileCmd(cmd):
    global currentFunc, index, localVars, globalVars, funcNames

    funcHolder = currentFunc

    # TODO: Properly recognize labels as control flow
    if type(cmd) == Label:
        return None
    if type(cmd) == Command:
        c = cmd.command
        if c in [0x0, 0x1, 0x2, 0x3]: # Useless garbage
            return None
        elif c in [0x4, 0x5]: # Jumps
            pass
        elif c in [0x6, 0x8]: # Return item
            other, args = getArgs(1) 
            return other + [c_ast.Return(args[0])]
        elif c in [0x7, 0x9]: # Return nothing
            return c_ast.Return()
        elif c in [0xA, 0xD]: # Push constant
            if type(cmd.parameters[0]) == ScriptRef:
                return c_ast.ID(str(cmd.parameters[0]))
            return c_ast.Constant(cmd.parameters[0])
        elif c == 0xB: # Push variable
            if cmd.parameters[0] == 0:
                return localVars[cmd.parameters[1]]
            else:
                return globalVars[cmd.parameters[1]]
        elif c in [0xe, 0xf, 0x10, 0x11, 0x12, 0x16, 0x17, 0x19, 0x1a, 0x1b, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x3a, 0x3b, 0x3c, 0x3d, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b]:
            other, args = getArgs(2)
            return other + [c_ast.BinaryOp(BINARY_OPERATIONS[c], args[1], args[0])]
        elif c in [0x13, 0x18, 0x2b, 0x3e]: # Negation, bit not, logic not, etc. (Unary Op not applied to variable)
            other, args = getArgs(1)
            return other + [c_ast.UnaryOp(UNARY_OPERATIONS[c], args[0])]
        elif c in [0x14, 0x15, 0x3f, 0x40]: # ++, --, etc. (Unary Op applied to variable)
            if cmd.parameters[0] == 0:
                return c_ast.UnaryOp(UNARY_OPERATIONS[c], localVars[cmd.parameters[1]])
            else:
                return c_ast.UnaryOp(UNARY_OPERATIONS[c], globalVars[cmd.parameters[1]])
        elif c in [0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x41, 0x42, 0x43, 0x44, 0x45]: # varset, floatvarset, etc.
            other, args = getArgs(1)
            if cmd.parameters[0] == 0:
                variable = localVars[cmd.parameters[1]]
            else:
                variable = globalVars[cmd.parameters[1]]
            return other + [c_ast.Assignment(ASSIGNMENT_OPERATIONS[c], variable, args[0])]
        elif c == 0x2c: # printf
            other, args = getArgs(cmd.parameters[0])
            return other + [c_ast.FuncCall("printf", c_ast.DeclList(args[::-1]))]
        elif c == 0x2d: # syscall
            other, args = getArgs(cmd.parameters[0])
            return other + [c_ast.FuncCall("sys_%X" % cmd.parameters[1], c_ast.DeclList(args[::-1]))] 
        elif c == 0x30: # set_main
            other, args = getArgs(cmd.parameters[0] + 1)
            if type(args[0]) == c_ast.Constant and type(args[0].value) == str:
                args[0] = c_ast.ID(args[0].value)
            return other + [c_ast.FuncCall("set_main", c_ast.DeclList(args[0:1] + args[:0:-1]))] #args[0:1] + args[:0:-1] is the first arg then the rest are in opposite order
        elif c == 0x31: # callFunc3
            other, args = getArgs(cmd.parameters[0] + 1)
            if type(args[0]) == c_ast.Constant and type(args[0].value) == str:
                args[0] = c_ast.ID(args[0].value)
            return other + [c_ast.FuncCall("callFunc3", c_ast.DeclList(args[0:1] + args[:0:-1]))]
    elif type(cmd) == FunctionCallGroup:
        oldFunc = currentFunc
        oldIndex = index

        currentFunc = cmd
        index = len(currentFunc) - 2 # (ignore the label that will be at the end)
        if currentFunc[index].command != 0x2f:
            raise DecompilerError("Function improperly formatted")
        
        cmd = currentFunc[index]
        other, args = getArgs(cmd.parameters[0] + 1)

        if type(args[0]) == c_ast.ID and not args[0].name in funcNames:
            args[0] = c_ast.UnaryOp("*", args[0])

        if type(args[0]) == c_ast.Constant and type(args[0].value) == str:
            args[0] = c_ast.ID(args[0].value)

        currentFunc = oldFunc
        index = oldIndex

        return other + [c_ast.FuncCall(args[0], c_ast.DeclList(args[:0:-1]))]
    elif type(cmd) == Cast:
        other, args = getArgs(1)
        return other + [c_ast.Cast(cmd.type, args[0])]

# Put function calls into a seperate groups
# this relocates casts into inline objects and puts function calls into their own object
# so they can be seen as one command with a push bit, also moves control flow into seperate objects
# to later be decompiled recursively
def pullOutGroups(commands):
    newCommands = []
    i = 0
    while i < len(commands):
        cmd = commands[i]
        if type(cmd) == Command and cmd.command == 0x2e:
            funCallGroup = []
            tryEnd = cmd.parameters[0]
            i += 1
            while commands[i] != tryEnd:
                funCallGroup.append(commands[i])
                i += 1
            funCallGroup.append(tryEnd)
            temp = pullOutGroups(funCallGroup)
            funCallGroup = FunctionCallGroup(cmd.pushBit)
            funCallGroup += temp
            newCommands.append(funCallGroup)
            newCommands.append(tryEnd)
        elif type(cmd) == Command and cmd.command in [0x38, 0x39]:
            index = len(newCommands) - 1
            numPushedBack = 0
            while index > 0:
                if type(newCommands[index]) in [Command, FunctionCallGroup] and newCommands[index].pushBit and numPushedBack == cmd.parameters[0]:
                    newCommands.insert(index + 1, Cast("float" if cmd.command == 0x38 else "int"))
                    break
                if type(newCommands[index]) == Command:
                    numPushedBack -= COMMAND_STACKPOPS[newCommands[index].command](newCommands[index].parameters) - int(newCommands[index].pushBit)
                elif type(newCommands[index]) == FunctionCallGroup:
                    numPushedBack += int(newCommands[index].pushBit)
                index -= 1
        else:
            newCommands.append(cmd)
        i += 1
    return newCommands

# Decopmiles the commands of the function and stores the resulting AST in the list s
def decompileFunc(func, s):
    global currentFunc, index
    currentFunc = func
    currentFunc.cmds = pullOutGroups(currentFunc.cmds)
    index = len(currentFunc) - 1
    insertPos = len(s)
    while index >= 0:
        decompiledCmd = decompileCmd(func[index])
        if decompiledCmd:
            if type(decompiledCmd) == list:
                for i in decompiledCmd:
                    if i != None:
                        s.insert(insertPos, i)
            else:
                if decompiledCmd != None:
                    s.insert(insertPos, decompiledCmd)
        index -= 1

# Takes a function and decompiles it, including setting up local variables
# returns the decompiled function
def decompile(func, funcNum):
    global localVars, funcTypes

    f = c_ast.FuncDef(funcTypes[funcNum], func.name, c_ast.DeclList(), c_ast.Statements())
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

# Detect all the global vars referenced in the file (and any that must exist) and return them
# returns a list of c_ast.Decl objects (type and name)
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

    globalVarTypes = ["int" for i in range(globalVarCount + 1)]
    for i in range(globalVarCount + 1):
        if i in varInt or i in varFloat:
            intCount = varInt[i] if i in varInt else 0
            floatCount = varFloat[i] if i in varFloat else 0
            if floatCount > intCount:
                globalVarTypes[i] = "float"

    return [c_ast.Decl(globalVarTypes[i], "global{}".format(i)) for i in range(globalVarCount + 1)]

# Takes the global variables and functions and prints them out as C to a file
def printC(globalVars, funcs, file=None):
    for decl in globalVars:
        print(str(decl) + ";", file=file)

    print(file=file)

    for func in funcs:
        print(func, file=file)
        print(file=file)

# Attempt to determine return type of each function
# returns a list of strings representing the return type of each function
def getFuncTypes(mscFile):
    global globalVarDecls
    funcTypes = [None for _ in range(len(mscFile))]
    numPasses = 0
    while None in funcTypes and numPasses < 4:
        numPasses += 1
        for i, func in enumerate(mscFile):
            if funcTypes[i] != None:
                continue
            hasReturnValue = False
            returnIndices = []
            for j, cmd in enumerate(func):
                if type(cmd) == Command and cmd.command in [0x6, 0x8]:
                    returnIndices.append(j)
                    hasReturnValue = True
                    
            if not hasReturnValue:
                funcTypes[i] = "void"
                continue

            typeConfirmedLevel = {"string" : 0, "float" : 0, "int" : 0, "bool" : 0}
            def setTypeLevel(type, level):
                if typeConfirmedLevel[type] < level:
                    typeConfirmedLevel[type] = level
            for returnIndex in returnIndices:
                if type(func[returnIndex - 1]) == Command:
                    if not func[returnIndex - 1].pushBit:
                        continue
                    c = func[returnIndex - 1].command
                    if c in [0xA, 0xD]:
                        t = {str : "string", int : "int", float : "float"}[type(func[returnIndex - 1].parameters[0])]
                        setTypeLevel(t, 1)
                    elif c == 0xb and func[returnIndex - 1].parameters[0] == 1:
                        var = globalVarDecls[func[returnIndex - 1].parameters[1]]
                        setTypeLevel(var.type, 1)
                    elif c in range(0xe, 0x25):
                        setTypeLevel("int", 2)
                    elif c in range(0x3a, 0x42):
                        setTypeLevel("float", 2)
                    elif c in range(0x46, 0x4c) or c in range(0x25, 0x2c):
                        setTypeLevel("bool", 2)
            if not 1 in typeConfirmedLevel.values() and not 2 in typeConfirmedLevel.values():
                continue
            maxType = max(typeConfirmedLevel.items(), key=operator.itemgetter(1))[0]
            funcTypes[i] = maxType
    for i in range(len(funcTypes)):
        if funcTypes[i] == None:
            funcTypes[i] = "int"
    return funcTypes

def main():
    global globalVars, globalVarDecls, funcTypes, funcNames

    mscFile = mscsb_disasm("captain.mscsb")
    
    globalVarDecls = getGlobalVars(mscFile)

    globalVars = [c_ast.ID(decl.name) for decl in globalVarDecls]
    funcs = []
    
    funcTypes = getFuncTypes(mscFile)

    # Rename entrypoint function to "main"
    mscFile.getScriptAtLocation(mscFile.entryPoint).name = 'main'
    
    funcNames = []
    for script in mscFile:
        funcNames.append(script.name)

    for i, script in enumerate(mscFile):
        funcs.append(decompile(script, i))

    with open("testDecompileFalcon.c", "w") as f:
        printC(globalVarDecls, funcs, f)

if __name__ == "__main__":
    main()