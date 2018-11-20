from msc import *
from xml_info import MscXmlInfo, VariableLabel
from argparse import ArgumentParser
import ast2str as c_ast
from disasmlib import disasm as mscsb_disasm
from disasmlib import Label, ScriptRef
import operator, os, timeit

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

class IfElseIntermediate:
    def __init__(self, ifCommands, elseCommands=None):
        self.isNot = False
        self.pushBit = False
        self.ifCommands = ifCommands
        self.elseCommands = elseCommands

class WhileIntermediate:
    def __init__(self, isDowWhile, commands, isIfNot):
        self.isDoWhile = isDowWhile
        self.isIfNot = isIfNot
        self.commands = commands

FLOAT_RETURN_SYSCALLS = [0x08, 0x0a, 0x0f, 0x11, 0x13, 0x15, 0x17, 0x1b, 0x25, 0x28, 0x2b, 0x2c, 0x2f, 0x32, 0x34, 0x35, 0x3d, 0x3f, 0x40, 0x45]
FLOAT_VAR_COMMANDS = [0x3f, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45]
INT_VAR_COMMANDS = [0x14, 0x15, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24]
VAR_COMMANDS = INT_VAR_COMMANDS + FLOAT_VAR_COMMANDS + [0xb]
USES_INT = [0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x24, 0x25, 0x26, 0x27, 28, 0x29, 0x2a]
USES_FLOAT = [0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b]
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

# Detect all the global vars referenced in the file (and any that must exist) and return them
# returns a list of c_ast.Decl objects (type and name)
def getGlobalVars(mscFile):
    varInt = {}
    varFloat = {}
    globalVarCount = 0
    for func in mscFile:
        for i,cmd in enumerate(func):
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
                elif cmd.command in FLOAT_VAR_COMMANDS:
                    if not varNum in varFloat:
                        varFloat[varNum] = 1
                    else:
                        varFloat[varNum] += 1
                elif cmd.command == 0xb:
                    i += 1
                    stackSize = 1
                    while i < len(func):
                        if type(func[i]) == Command:
                            if func[i].command in [0x38, 0x39]:
                                break
                            stackSize -= COMMAND_STACKPOPS[func[i].command](func[i].parameters)
                            if stackSize <= 0:
                                if func[i].command in USES_FLOAT:
                                    if not varNum in varFloat:
                                        varFloat[varNum] = 1
                                    else:
                                        varFloat[varNum] += 1
                                elif func[i].command in USES_INT:
                                    if not varNum in varInt:
                                        varInt[varNum] = 1
                                    else:
                                        varInt[varNum] += 1
                                break
                            stackSize += 1 if func[i].pushBit else 0
                        i += 1

    globalVarTypes = ["int" for i in range(globalVarCount + 1)]
    for i in range(globalVarCount + 1):
        if i in varInt or i in varFloat:
            intCount = varInt[i] if i in varInt else 0
            floatCount = varFloat[i] if i in varFloat else 0
            if floatCount > intCount:
                globalVarTypes[i] = "float"

    return [c_ast.Decl(globalVarTypes[i], "global{}".format(i)) for i in range(globalVarCount + 1)]

# Gets the local variable types for a function
# is merely an educated guess based on what commands
# reference it.
def getLocalVarTypes(func, varCount):
    varInt = {}
    varFloat = {}
    for i,cmd in enumerate(func):
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
            elif cmd.command == 0xb:
                i += 1
                stackSize = 1
                while i < len(func):
                    if type(func[i]) == Command:
                        if func[i].command in [0x38, 0x39]:
                            break
                        stackSize -= COMMAND_STACKPOPS[func[i].command](func[i].parameters)
                        if stackSize <= 0:
                            if func[i].command in USES_FLOAT:
                                if not varNum in varFloat:
                                    varFloat[varNum] = 1
                                else:
                                    varFloat[varNum] += 1
                            elif func[i].command in USES_INT:
                                if not varNum in varInt:
                                    varInt[varNum] = 1
                                else:
                                    varInt[varNum] += 1
                            break
                        stackSize += 1 if func[i].pushBit else 0
                    i += 1

    localVarTypes = ["int" for i in range(varCount)]
    for i in range(varCount):
        if i in varInt or i in varFloat:
            intCount = varInt[i] if i in varInt else 0
            floatCount = varFloat[i] if i in varFloat else 0
            if floatCount > intCount:
                localVarTypes[i] = "float"

    return localVarTypes

# Recursively check if binary tree of just lists/ints
def ternaryToArray(obj):
    if type(obj) == c_ast.TernaryOp:
        return [ternaryToArray(obj.trueStatement), ternaryToArray(obj.falseStatement)]
    elif type(obj) == c_ast.Constant and type(obj.value) == int and obj.value in [0, 1]:
        return obj.value
    else:
        return None

def validArrayRepresentation(arrayRepresentation):
    return (type(arrayRepresentation) == list and
            len(arrayRepresentation) == 2 and
            (arrayRepresentation[0] in [0, 1] or validArrayRepresentation(arrayRepresentation[0])) and
            (arrayRepresentation[1] in [0, 1] or validArrayRepresentation(arrayRepresentation[1])))

def flipInside(arrayRepresentation):
    if type(arrayRepresentation[0]) == list:
        return [arrayRepresentation[0][::-1], arrayRepresentation[1]]
    else:
        return [arrayRepresentation[0], arrayRepresentation[1][::-1]]

def ifToTernaryOp(ifStatement):
    if ifStatement.falseStatements != None:
        while None in ifStatement.falseStatements:
            ifStatement.falseStatements.remove(None)
    if ifStatement.trueStatements != None:
        while None in ifStatement.trueStatements:
            ifStatement.trueStatements.remove(None)
    if ifStatement.falseStatements == None or len(ifStatement.falseStatements) != 1 or len(ifStatement.trueStatements) != 1:
        raise DecompilerError("Error: found a bad if/else ternary block")
    if type(ifStatement.trueStatements[0]) == c_ast.If:
        ifStatement.trueStatements[0] = ifToTernaryOp(ifStatement.trueStatements[0])
    if type(ifStatement.falseStatements[0]) == c_ast.If:
        ifStatement.falseStatements[0] = ifToTernaryOp(ifStatement.falseStatements[0])

    ternaryTemp = c_ast.TernaryOp(ifStatement.condition, ifStatement.trueStatements[0], ifStatement.falseStatements[0])
    if type(ternaryTemp.trueStatement) == c_ast.TernaryOp or type(ternaryTemp.falseStatement) == c_ast.TernaryOp:
        arrayRepresentation = ternaryToArray(ternaryTemp)
        if validArrayRepresentation(arrayRepresentation):
            # both items are either an int or a
            a = ternaryTemp.condition
            while type(a) == c_ast.UnaryOp and a.op == "!":
                arrayRepresentation = arrayRepresentation[::-1]
                a = a.id
            b = (ternaryTemp.trueStatement.condition
                if type(ternaryTemp.trueStatement) == c_ast.TernaryOp
                else ternaryTemp.falseStatement.condition)
            while type(b) == c_ast.UnaryOp and b.op == "!":
                arrayRepresentation = flipInside(arrayRepresentation)
                b = b.id
            # Forgive me for I have sinned
            # this is an attempt to convert ternary operations to boolean operations
            if arrayRepresentation in [[0, [0,0]], [[0, 0], 0]]:
                return c_ast.Constant(0)
            if arrayRepresentation in [[1, [1, 1]], [[1, 1], 1]]:
                return c_ast.Constant(1)
            if arrayRepresentation in [[1, [0, 0]], [[1, 1], 0]]:
                return a
            if arrayRepresentation in [[0, [1, 1]], [[0, 0], 1]]:
                return c_ast.UnaryOp("!", a)
            if arrayRepresentation == [0, [0, 1]]:
                return c_ast.UnaryOp("!", c_ast.BinaryOp("||", a, b))
            if arrayRepresentation == [[0, 1], 1]:
                return c_ast.UnaryOp("!", c_ast.BinaryOp("&&", a, b))
            if arrayRepresentation == [1, [0, 1]]:
                return c_ast.BinaryOp("||", a, c_ast.UnaryOp("!", b))
            if arrayRepresentation == [[1, 0], 1]:
                return c_ast.BinaryOp("||", c_ast.UnaryOp("!", a), b)
            if arrayRepresentation == [0, [1, 0]]:
                return c_ast.BinaryOp("&&", c_ast.UnaryOp("!", a), b)
            if arrayRepresentation == [1, [1, 0]]:
                return c_ast.BinaryOp("||", a, b)
            if arrayRepresentation == [[0, 1], 0]:
                return c_ast.BinaryOp("&&", a, c_ast.UnaryOp("!", b))
            if arrayRepresentation == [[1, 0], 0]:
                return c_ast.BinaryOp("&&", a, b)
    return ternaryTemp

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
        thisIndex = index
        d = decompileCmd(currentFunc[index])
        if type(d) == list:
            other = d[:-1] + other
            d = d[-1]
        if ((type(currentFunc[thisIndex]) in [Command, FunctionCallGroup, IfElseIntermediate]) and currentFunc[thisIndex].pushBit) or type(currentFunc[thisIndex]) == Cast:
            args.append(d)
        else:
            other.append(d)
    for i in range(len(args)):
        if type(args[i]) == c_ast.If:
            args[i] = ifToTernaryOp(args[i])
    other = list(filter(lambda a: a != None, other))
    return other, args

# Recursively decompile from commands to an AST, uses global variable "index" to keep track of position,
# iterating backwards through the function in order to assign arguments to the things that use them.
def decompileCmd(cmd):
    global currentFunc, index, localVars, globalVars, funcNames, xmlInfo

    funcHolder = currentFunc

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
            syscallInfo = xmlInfo.getSyscall(cmd.parameters[1])
            if syscallInfo != None:
                if RepresentsInt(str(args[-1])):
                    methodInfo = syscallInfo.getMethod(int(str(args[-1]), 0))
                    if methodInfo != None:
                        return other + [c_ast.FuncCall(c_ast.StructRef(syscallInfo.name, methodInfo.name), c_ast.DeclList(args[-2::-1]))]
                return other + [c_ast.FuncCall(syscallInfo.name, c_ast.DeclList(args[::-1]))]
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

        while index > 0:
            d = decompileCmd(currentFunc[index])
            if type(d) == list:
                other = d + other
            else:
                other.insert(0, d)
            index -= 1

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
    elif type(cmd) == IfElseIntermediate:
        beforeIf, args = getArgs(1)
        if len(args) == 0:
            return beforeIf
        ifCondition = args[0]
        oldFunc = currentFunc
        oldIndex = index
        trueStatements = c_ast.Statements()
        currentFunc = cmd.ifCommands
        index = len(currentFunc) - 1
        while index >= 0:
            d = decompileCmd(currentFunc[index])
            if type(d) == list:
                for i in d[::-1]:
                    if i != None:
                        trueStatements.insert(0, i)
            elif d != None:
                trueStatements.insert(0, d)
            index -= 1
        if cmd.elseCommands != None:
            currentFunc = cmd.elseCommands
            index = len(currentFunc) - 1
            falseStatements = c_ast.Statements()
            while index >= 0:
                d = decompileCmd(currentFunc[index])
                if type(d) == list:
                    for i in d[::-1]:
                        if i != None:
                            falseStatements.insert(0, i)
                elif d != None:
                    falseStatements.insert(0, d)
                index -= 1
        else:
            falseStatements = None
        currentFunc = oldFunc
        index = oldIndex
        if cmd.isNot:
            ifCondition = c_ast.UnaryOp("!", ifCondition)
        return beforeIf + [c_ast.If(ifCondition, trueStatements, falseStatements)]
    elif type(cmd) == WhileIntermediate:
        oldFunc = currentFunc
        oldIndex = index
        loopStatements = c_ast.Statements()
        currentFunc = cmd.commands
        index = len(currentFunc)
        other, condition = getArgs(1)
        index -= 1
        condition = condition[0]
        for i in other[::-1]:
            loopStatements.insert(0, i)
        while index >= 0:
            d = decompileCmd(currentFunc[index])
            if type(d) == list:
                for i in d[::-1]:
                    if i != None:
                        loopStatements.insert(0, i)
            elif d != None:
                loopStatements.insert(0, d)
            index -= 1
        currentFunc = oldFunc
        index = oldIndex
        if not cmd.isIfNot:
            condition = c_ast.UnaryOp("!", condition)
        if cmd.isDoWhile:
            return c_ast.DoWhile(condition, loopStatements)
        else:
            return c_ast.While(condition, loopStatements)
    elif type(cmd) == c_ast.Break:
        return cmd

# Decopmiles the commands of the function and stores the resulting AST in the list s
def decompileFunc(func, s):
    global currentFunc, index
    currentFunc = func
    currentFunc.cmds = pullOutGroups(pullOutLoops(currentFunc.cmds))
    index = len(currentFunc) - 1
    insertPos = len(s)
    while index >= 0:
        decompiledCmd = decompileCmd(func[index])
        if decompiledCmd:
            if type(decompiledCmd) == list:
                for i in decompiledCmd[::-1]:
                    if i != None:
                        s.insert(insertPos, i)
            elif decompiledCmd != None:
                s.insert(insertPos, decompiledCmd)
        index -= 1

# Takes a function and decompiles it, including setting up local variables
# returns the decompiled function
def decompile(func, funcNum):
    global localVars, funcTypes, allLocalVarTypes
    f = c_ast.FuncDef(funcTypes[funcNum], func.name, c_ast.DeclList(), c_ast.Statements())
    #try:
    # If non-empty function that doesn't start with 0x2
    if len(func.cmds) != 0 and func.cmds[0].command != 0x2:
        raise DecompilerError("Script {} doesn't start with a begin".format(func.name))
    beginCommand = func.cmds[0]
    argc = beginCommand.parameters[0]
    varc = beginCommand.parameters[1]
    localVarTypes = getLocalVarTypes(func, varc)
    allLocalVarTypes.append(localVarTypes)
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
    #except Exception as e: 
    #    f.statements = c_ast.Statements([c_ast.Comment("Error occurred while decompiling:\n{}".format(str(e)))])
    return f

# Gets last object of type Command from list l
def lastCommand(l):
    for i in l[::-1]:
        if type(i) != Label:
            return i

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
            while index >= 0:
                if type(newCommands[index]) in [Command, FunctionCallGroup] and newCommands[index].pushBit and numPushedBack == cmd.parameters[0]:
                    newCommands.insert(index + 1, Cast("float" if cmd.command == 0x38 else "int"))
                    break
                if type(newCommands[index]) == Command:
                    numPushedBack -= COMMAND_STACKPOPS[newCommands[index].command](newCommands[index].parameters) - int(newCommands[index].pushBit)
                elif type(newCommands[index]) == FunctionCallGroup:
                    numPushedBack += int(newCommands[index].pushBit)
                index -= 1
        elif type(cmd) == Command and cmd.command in [0x34, 0x35]:
            isIfNot = (cmd.command == 0x35)
            labelPosition = commands.index(cmd.parameters[0])
            if labelPosition == -1:
                raise DecompilerError("Label for if/ifNot not found at {}".format(cmd.commandPosition))
            if labelPosition < i:
                raise DecompilerError("Loops are not supported yet")
            # Handle empty if
            elif commands[labelPosition - 1] == cmd:
                intermediate = IfElseIntermediate([])
                intermediate.isNot = isIfNot
                newCommands.append(intermediate)
            # Handle weird edge case, see script_6 of character standard lib
            elif type(commands[labelPosition - 1]) == Command and commands[labelPosition - 1].command in [0x34, 0x35]:
                badIfLabelPos = commands.index(commands[labelPosition - 1].parameters[0])
                if type(commands[badIfLabelPos - 1]) == Command and commands[badIfLabelPos - 1].command == 0x36:
                    badElseLabelPos = commands.index(commands[badIfLabelPos - 1].parameters[0])
                    intermediate = IfElseIntermediate(pullOutGroups(commands[i + 1:badElseLabelPos+1]), pullOutGroups(commands[labelPosition + 1:badIfLabelPos-1]))
                    intermediate.pushBit = len(intermediate.ifCommands) > 0 and lastCommand(intermediate.ifCommands).pushBit
                    intermediate.isNot = isIfNot
                    i = badElseLabelPos
                elif labelPosition == badIfLabelPos:
                    intermediate = IfElseIntermediate(pullOutGroups(commands[i + 1:labelPosition + 1]))
                    intermediate.isNot = isIfNot
                    newCommands.append(intermediate)
                    i = labelPosition
                else:
                    raise DecompilerError("What even happened")
                newCommands.append(intermediate)
            elif type(commands[labelPosition - 1]) == Command and commands[labelPosition - 1].command == 0x36:
                elseLabel = commands[labelPosition - 1].parameters[0]
                elseLabelPos = commands.index(elseLabel)
                if elseLabel == -1:
                    raise DecompilerError("Label for else not found")
                copyElse = False
                for j in range(i + 1, labelPosition - 1):
                    if type(commands[j]) == Command and commands[j].command in [0x34, 0x35] and commands[j].parameters[0] == cmd.parameters[0]:
                        copyElse = True
                        break
                if copyElse:
                    intermediate = IfElseIntermediate(pullOutGroups(commands[i + 1:elseLabelPos+1]), pullOutGroups(commands[labelPosition + 1:elseLabelPos+1]))
                    intermediate.pushBit = len(intermediate.ifCommands) > 0 and lastCommand(intermediate.ifCommands).pushBit
                else:
                    intermediate = IfElseIntermediate(pullOutGroups(commands[i + 1:labelPosition - 1]), pullOutGroups(commands[labelPosition + 1:elseLabelPos+1]))
                    intermediate.pushBit = len(intermediate.ifCommands) > 0 and lastCommand(intermediate.ifCommands).pushBit
                intermediate.isNot = isIfNot
                newCommands.append(intermediate)
                i = elseLabelPos
            else:
                intermediate = IfElseIntermediate(pullOutGroups(commands[i + 1:labelPosition + 1]))
                intermediate.isNot = isIfNot
                newCommands.append(intermediate)
                i = labelPosition
        else:
            newCommands.append(cmd)
        i += 1
    return newCommands

def pullOutLoops(commands):
    newCommands = []
    i = len(commands) - 1
    while i >= 0:
        cmd = commands[i]
        if type(cmd) == Command and cmd.command in [0x34, 0x35] and commands.index(cmd.parameters[0]) < i:
            isIfNot = (cmd.command == 0x35)
            labelPosition = commands.index(cmd.parameters[0])
            isDoWhile =  not (type(commands[labelPosition-1]) == Command and
                              commands[labelPosition-1].command in [4, 5, 54] and
                              commands[labelPosition-1].parameters[0] in commands[labelPosition:i])
            if type(commands[i+1]) == Label:
                endLabel = commands[i+1]
                for j in range(labelPosition, i):
                    if type(commands[j]) == Command and commands[j].command in [0x4, 0x5, 0x36] and commands[j].parameters[0] == endLabel:
                        commands[j] = c_ast.Break()
            newCommands.insert(0, WhileIntermediate(isDoWhile, pullOutGroups(pullOutLoops(commands[labelPosition:i])), isIfNot))
            i = labelPosition + 1
        else:
            newCommands.insert(0, commands[i])
        i -= 1
    return newCommands

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
    global globalVarDecls, allLocalVarTypes, funcNames
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
                    elif c == 0xb and func[returnIndex - 1].parameters[0] == 0:
                        setTypeLevel(allLocalVarTypes[i][func[returnIndex - 1].parameters[1]], 1)
                    elif c in range(0xe, 0x25):
                        setTypeLevel("int", 2)
                    elif c == 0x2d and func[returnIndex - 1].parameters[1] in FLOAT_RETURN_SYSCALLS:
                        setTypeLevel("float", 2)
                    elif c in range(0x3a, 0x42):
                        setTypeLevel("float", 2)
                    elif c in range(0x46, 0x4c) or c in range(0x25, 0x2c):
                        setTypeLevel("int", 2)
                elif type(func[returnIndex - 1]) == Label and type(func[returnIndex - 2]) == FunctionCallGroup:
                    if func[returnIndex - 2][-3].command in [0xA, 0xD] and func[returnIndex - 2][-3].parameters[0] in funcNames:
                        typeConfirmedLevel[func[returnIndex - 2][-3].parameters[0]] = 1
            if not 1 in typeConfirmedLevel.values() and not 2 in typeConfirmedLevel.values():
                continue
            maxType = max(typeConfirmedLevel.items(), key=operator.itemgetter(1))[0]
            funcTypes[i] = maxType
    for i in range(len(funcTypes)):
        if funcTypes[i] == None:
            funcTypes[i] = "int"
        elif funcTypes[i] in funcNames:
            MAX_RECURSION = 10000
            recursiveLevel = 0
            while funcTypes[i] in funcNames:
                recursiveLevel += 1
                if recursiveLevel > MAX_RECURSION:
                    break # Prevent an infinite loop by timing out after MAX_RECURSION tries
                funcTypes[i] = funcTypes[funcNames.index(funcTypes[i])]
    return funcTypes

def main(args):
    global globalVars, globalVarDecls, funcTypes, funcNames, allLocalVarTypes, xmlInfo

    xmlInfo = MscXmlInfo("labels.xml")

    print("Analyzing...")
    mscFile = mscsb_disasm(args.file)
    print("Decompiling...")

    globalVarDecls = getGlobalVars(mscFile)

    globalVars = [c_ast.ID(decl.name) for decl in globalVarDecls]
    funcs = []
    funcTypes = [None for _ in range(len(mscFile))]

    # Rename entrypoint function to "main"
    mscFile.getScriptAtLocation(mscFile.entryPoint).name = 'main'
    funcNames = []
    for script in mscFile:
        funcNames.append(script.name)

    allLocalVarTypes = []
    for i, script in enumerate(mscFile):
        funcs.append(decompile(script, i))
    funcTypes = getFuncTypes(mscFile)
    for i, func in enumerate(funcs):
        func.type = funcTypes[i]

    if args.split:
        stdlibFuncs = []
        while funcs[0].name != "main":
            stdlibFuncs.append(funcs.pop(0))
        with open("stdlib.c", "w") as f:
            printC(globalVarDecls, stdlibFuncs, f)
        with open(args.filename if args.filename != None else (os.path.basename(os.path.splitext(args.file)[0]) + '.c'), "w") as f:
            print('#include "stdlib.c"', file=f)
            printC([], funcs, f)
    else:
        with open(args.filename if args.filename != None else (os.path.basename(os.path.splitext(args.file)[0]) + '.c'), "w") as f:
            printC(globalVarDecls, funcs, f)

if __name__ == "__main__":
    parser = ArgumentParser(description="Decompile MSC bytecode to C")
    parser.add_argument('file', type=str, help='file to decompile')
    parser.add_argument('-o', dest='filename', help='Filename to output to')
    parser.add_argument('-s', '--split', action='store_true', help='Split to put all functions before main() into stdlib.c')
    start = timeit.default_timer()
    main(parser.parse_args())
    end = timeit.default_timer()
    print('Execution completed in %f seconds' % (end - start))
