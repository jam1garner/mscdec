#**************************************************************************#
# This file is part of pymsc which is released under MIT License. See file #
# LICENSE or go to https://github.com/jam1garner/pymsc/blob/master/LICENSE #
# for full license details.                                                #
#**************************************************************************#
from msc import *
import sys, os, time, os.path, timeit
from argparse import ArgumentParser
from struct import unpack, pack
from math import isnan

scriptNames = {}
scriptOffsets = []
scriptCalls = {}

gvIsOffset = [False for i in range(64)]
for gv in [7] + list(range(11,17)) + [21,22,23,25,26,27,28,30,34,35,36,37,39,40,41,42,43,44,56,57,58,59,60,61]:
    gvIsOffset[gv] = True

class Label:
    def __init__(self, name=None):
        self.name = name

    def __str__(self):
        if self.name:
            return self.name+":"
        else:
            return "Label "+hex(id(self))+":"

class ScriptRef(str):
    pass

def updateScriptReference(popped, index, scriptName):
    global scriptCalledVars, mscFile, acmdNames, charAcmdNames
    try:
        #if the Xth command popped off the stack is pushing a constant
        if popped[index].command in [0xA, 0xD]:
            #if the index pushed is a valid script offset
            if popped[index].parameters[0] in scriptOffsets:
                newScriptName = scriptNames[popped[index].parameters[0]]
                popped[index].parameters[0] = ScriptRef(newScriptName)

        #if the Xth command popped off the stack is a variable
        if popped[index].command == 0xB:
            #if the variable is local
            if popped[index].parameters[0] == 0:
                if not scriptName in scriptCalledVars:
                    scriptCalledVars[scriptName] = []
                if not popped[index].parameters[1] in scriptCalledVars[scriptName]:
                    scriptCalledVars[scriptName].append(popped[index].parameters[1])
    except:
        print(scriptName)
        raise

#script - mscScript object
#startIndex - index in the script to start at, used for recursively evaluating all paths
#stack - the current stack, blank at start of script and passed through recursively when evaluating paths
#endPosition - when to stop searching (i.e. when the stack is empty and paths recombine)
#depth - used to determine whether or not a path can be abandoned
def emuScript(script, startIndex, stack, passCount, endPosition=None, depth=0):
    global clearedPaths,scriptCalledVars, mscFile
    scriptName = scriptNames[script.bounds[0]]
    if endPosition == None:
        clearedPaths = []
    try:
        i = startIndex
        while i < len(script):
            if endPosition != None and i >= endPosition and len(stack) == 0:
                return False
            #Get the number of pops based on the command and it's parameters
            popCount = COMMAND_STACKPOPS[script[i].command](script[i].parameters)
            popped = []
            try:
                for _ in range(popCount):
                    #Pop the needed commands into the popped list in case one of them is needed
                    popped.append(stack.pop())
            except:
                pass

            #First pass
            if passCount == 0:
                #if the command is a function call
                if script[i].command in [0x2f, 0x30, 0x31]:
                    updateScriptReference(popped, 0, scriptName)
                #if the command is a printf
                if script[i].command == 0x2c and popped[-1].command in [0xA, 0xD]:
                    if type(popped[-1].parameters[0]) != str:
                        popped[-1].parameters[0] = mscFile.strings[popped[-1].parameters[0]]
                #if the command in a sys call
                if script[i].command == 0x2d:
                    if script[i].parameters[1] == 0:
                        updateScriptReference(popped, 0, scriptName)
                    elif script[i].parameters[1] == 3:
                        updateScriptReference(popped, 0, scriptName)
                    elif script[i].parameters[1] == 0x29:
                        updateScriptReference(popped, 1, scriptName)
                    elif script[i].parameters[1] == 0x29:
                        updateScriptReference(popped, 2, scriptName)
                #If gv16 flag is enabled and it is setting GlobalVar16
                if script[i].command == 0x1C and script[i].parameters[0] == 0x1 and gvIsOffset[script[i].parameters[1]]:
                    updateScriptReference(popped, 0, scriptName)
            elif passCount >= 1:
                if script[i].command in [0x1C, 0x41] and scriptName in scriptCalledVars:
                    if script[i].parameters[0] == 0 and script[i].parameters[1] in scriptCalledVars[scriptName]:
                        updateScriptReference(popped, 0, scriptName)
                if script[i].command in [0x2f, 0x30, 0x31]:
                    if popped[0].command in [0xA, 0xD]:
                        jumpScriptName = None
                        if isinstance(popped[0].parameters[0], int) and popped[0].parameters[0] in scriptNames:
                            jumpScriptName = scriptNames[popped[0].parameters[0]]
                        elif isinstance(popped[0].parameters[0], str):
                            jumpScriptName = popped[0].parameters[0]

                        if jumpScriptName in scriptCalledVars:
                            for localVarNum in scriptCalledVars[jumpScriptName]:
                                if localVarNum+1 < len(popped):
                                    updateScriptReference(popped, -(localVarNum + 1), scriptName)

            #if the command is push, just readd the command before it
            if script[i].command == 0x32:
                stack.append(script[i-1])
            #if the pushBit is set, push the command onto the stack
            if script[i].pushBit:
                stack.append(script[i])
            #if the command is if or ifNot then evaluate both possible paths
            if script[i].command in [0x34, 0x35]:
                jumpIndex = script.getIndexOfInstruction(script[i].parameters[0])
                endOfBlock = jumpIndex
                if script[jumpIndex - 1].command in [4, 5, 0x36]:
                    endOfBlock = script.getIndexOfInstruction(script[jumpIndex - 1].parameters[0])
                    finished = emuScript(script, jumpIndex, stack, passCount, endOfBlock, depth+1)
                elif len(stack) > 0:
                    finished = emuScript(script, jumpIndex, stack, passCount, jumpIndex, depth+1)
                if not script[i].commandPosition in clearedPaths:
                    clearedPaths.append(script[i].commandPosition)
                else:
                    if depth != 0:
                        pass#return
            #if it hits a jump or else command, just jump it
            if script[i].command in [4, 5, 0x36]:
                newIndex = script.getIndexOfInstruction(script[i].parameters[0])
                if newIndex == None:
                    i += 1
                else:
                    i = newIndex
            else:
                #if it isn't a jump, move on to the next command
                i += 1
    except:
        raise
    return True

def guessIsFloat(bits):
    if bits == 0:
        return False
        
    sign = (bits & 0x80000000) != 0
    exp = ((bits & 0x7f800000) >> 23) - 127
    mant = bits & 0x007fffff

    testFloat = unpack("f", pack("I", bits))[0]
    if abs(testFloat) < 0.000001 or isnan(testFloat):
        return False
    elif sign:
        return True
    elif abs(testFloat) >= 10000000:
        return False

    # +- 0.0
    if exp == -127 and mant == 0:
        return True

    # +- 1 billionth to 1 billion
    if -30 <= exp and exp <= 30:
        return True

    # some value with only a few binary digits
    if (mant & 0x0000ffff) == 0:
        return True

    return False

def pickTypes(script):
    for cmd in script:
        if cmd.command in [0xa, 0xd]:
            if type(cmd.parameters[0]) == int:
                if guessIsFloat(cmd.parameters[0]):
                    asFloat = unpack("f", pack("I", cmd.parameters[0]))[0]
                    if not (asFloat > 0 and asFloat < 0.000001):
                        cmd.parameters[0] = asFloat

def disasm(fname):
    global clearedPaths,scriptCalledVars,mscFile,charAcmdNames

    mscFile = MscFile()

    with open(fname, 'rb') as f:
        mscFile.readFromFile(f)

    for i,script in enumerate(mscFile):
        if not script.bounds[0] in scriptOffsets:
            scriptNames[script.bounds[0]] = script.name
            scriptOffsets.append(script.bounds[0])

    scriptCalledVars = {}

    # 2 = number of passes for script offset analysis
    for i in range(2):
        for script in mscFile:
            clearedPaths = []
            emuScript(script, 0, [], i)

    for i,script in enumerate(mscFile):
        clearedPaths = []
        emuScript(script, 0, [], 2)
        pickTypes(script)

        jumpPositions = {}
        for cmd in script:
            if cmd.command in [0x4, 0x5, 0x2e, 0x34, 0x35, 0x36]:
                if not cmd.parameters[0] in jumpPositions:
                    jumpPositions[cmd.parameters[0]] = Label("loc_%X" % (cmd.parameters[0]))
                cmd.parameters[0] = jumpPositions[cmd.parameters[0]]

        j = 0
        while j < len(script):
            cmd = script[j]
            if cmd.commandPosition in jumpPositions:
                script.cmds.insert(j, jumpPositions[cmd.commandPosition])
                # Go ahead and skip over the label
                j += 1
            j += 1

    return mscFile