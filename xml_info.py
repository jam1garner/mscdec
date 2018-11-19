from xml.etree import ElementTree as ET
from enum import Enum

class VariableLabel:
    class Type(Enum):
        SYSCALL = 0
        GLOBAL = 1
        METHOD = 2
        FUNCTION = 3

    def __init__(self, id=None, name=None):
        self.id = id
        self.name = name
        self.methods = []

class MscXmlInfo:
    def __init__(self, filename=None):
        self.globals = []
        self.functions = []
        self.syscalls = []
        if file != None:
              self.read(file)

    def read(filename):
        labels = ET.parse(filename).getroot()
        for function in labels.find("functions").findall("function"):
            self.functions.append(VariableLabel(
                    function.find("id").text,
                    function.find("name").text
                ))
        for globalNode in labels.find("globals").findall("global"):
            self.globals.append(VariableLabel(
                    globalNode.find("id").text,
                    globalNode.find("name").text
                ))
        for syscall in labels.find("syscalls").findall("syscall"):
            syscallLabel = VariableLabel(
                        syscall.find("id").text,
                        syscall.find("name").text
                    )
            for method in syscall.find("methods").findall("method"):
                syscallLabel.methods.append(VariableLabel(
                        method.find("id").text,
                        method.find("name").text
                    ))


