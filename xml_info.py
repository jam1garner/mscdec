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


