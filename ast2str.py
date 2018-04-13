class Assignment:
    def __init__(self, op, lvalue, rvalue):
        self.op = op
        self.lvalue = lvalue
        self.rvalue = rvalue
    
    def __str__(self):
        return '{} {} {}'.format(str(self.lvalue), self.op, str(self.rvalue))


class BinaryOp:
    def __init__(self, op=None, arg1=None, arg2=None):
        self.op = op
        self.arg1 = arg1
        self.arg2 = arg2

    def __str__(self):
        formatString = ""
        formatString += "({}) {} " if type(self.arg1) in _parenthesisTypes else "{} {} "
        formatString += "({})" if type(self.arg2) in _parenthesisTypes else "{}"
        return formatString.format(str(self.arg1), self.op, str(self.arg2))

class Break:
    def __str__(self):
        return "break"

class Statements(list):
    def __str__(self):
        return '\n'.join([str(i) + ';' for i in self])

class Cast:
    def __init__(self, type, statement):
        self.type = type
        self.statement = statement

    def __str__(self):
        return "(({}){})".format(str(self.type), str(self.statement))

class Comment:
    def __init__(self, text):
        self.text = text

    def __str__(self):
        return '/*{}*/'.format(self.text)

class Constant:
    def __init__(self, value):
        self.value = value

    def __str__(self):
        if type(self.value) == str:
            return '"{}"'.format(self.value)
        elif type(self.value) == int:
            return hex(self.value)
        elif type(self.value) == bool:
            return str(self.value).lower()
        else:
            return str(self.value)

class Continue:
    def __str__(self):
        return "continue"

class Decl:
    def __init__(self, type=None, name=None, initialValue=None):
        self.type = type
        self.name = name
        self.initialValue = initialValue

    def __str__(self):
        if self.initialValue == None:
            return "{} {}".format(str(self.type), str(self.name))
        else:
            return "{} {} = {}".format(str(self.type), str(self.name), str(self.initialValue))

class DeclList(list):
    def __str__(self):
        return ', '.join([str(i) for i in self])

class DoWhile:
    def __init__(self, condition, statements):
        self.condition = condition
        self.statements = statements

    def __str__(self):
        return "do{{\n{}\n}}while({})".format(self.statements, self.condition)

class EmptyStatement:
    def __str__(self):
        return ""

class For:
    def __init__(self, initialize, condition, iterate, statements):
        self.initialize = initialize
        self.iterate = iterate
        self.condition = condition
        self.statements = statements

    def __str__(self):
        return "for({};{};{}){{\n{}\n}}".format(self.initialize, self.condition, self.iterate, self.statements)

class FuncCall:
    def __init__(self, function, args):
        self.function = function
        self.args = args

    def __str__(self):
        return "{}({})".format(str(self.function), str(self.args))

class FuncDef:
    def __init__(self, type, name, args, statements):
        self.type = type
        self.name = name
        self.args = args
        self.statements = statements

    def __str__(self):
        return "{} {}({}){{\n{}\n}}".format(str(self.type), str(self.name), str(self.args), str(self.statements))

class Goto:
    def __init__(self, labelName):
        self.labelName = labelName

    def __str__(self):
        return "goto {}".format(self.labelName)

class ID:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return self.name

class If:
    def __init__(self, condition, trueStatements, falseStatements):
        self.condition = condition
        self.trueStatements = trueStatements
        self.falseStatements = falseStatements

    def __str__(self):
        returnStr = "if({}) {{\n{}\n}}".format(str(self.condition), str(self.trueStatements))

        if self.falseStatements == None:
            pass
        elif len(self.falseStatements) == 1 and type(self.falseStatements[0]) == If:
            returnStr += " else {}".format(self.falseStatements[0])
        else:
            returnStr += " else {{\n{}\n}}".format(self.falseStatements)

        return returnStr

class Label:
    def __init__(self, name):
        self.name = name

    def __str__(self):
        return "{}:".format(self.name)

class Return:
    def __init__(self, statement=None):
        self.statement = statement

    def __str__(self):
        if self.statement == None:
            return "return"
        return "return {}".format(str(self.statement))

class TernaryOp:
    def __init__(self, condition, trueStatement, falseStatement):
        self.condition = condition
        self.trueStatement = trueStatement
        self.falseStatement = falseStatement

    def __str__(self):
        formatString = "({}) ? " if type(self.condition) in _parenthesisTypes else "{} ? "
        formatString += "({}) : " if type(self.trueStatement) in _parenthesisTypes else "{} : "
        formatString += "({})" if type(self.falseStatement) in _parenthesisTypes else "{}"
        return formatString.format(str(self.condition), str(self.trueStatement), str(self.falseStatement))

class UnaryOp:
    def __init__(self, op, id):
        self.op = op
        self.id = id

    def __str__(self):
        if self.op in ["++", "--"]:
            return "{}{}".format(str(self.id), str(self.op))
        elif self.op == "*":
            return "({}{})".format(str(self.op), str(self.id))
        else:
            return "{}{}".format(str(self.op), str(self.id))

class While:
    def __init__(self, condition, statements):
        self.condition = condition
        self.statements = statements

    def __str__(self):
        return "while({}){{\n{}\n}}".format(str(self.condition), str(self.statements))

_parenthesisTypes = [BinaryOp, TernaryOp]

# Example:
# void main(){
#     printf("Should be 8 - 5 + (true ? 3 : 4) = %i",5 + (true ? 3 : 4));
# }

# values = [c_ast.Constant(3), c_ast.Constant(4), c_ast.Constant(5), c_ast.Constant(True)]
# tern = c_ast.TernaryOp(values[3], values[0], values[1])
# add = c_ast.BinaryOp("+", values[2], tern)
# string = c_ast.Constant("Should be 8 - 5 + (true ? 3 : 4) = %i")
# printf = c_ast.FuncCall("printf", c_ast.DeclList([string, add]))
# main = c_ast.FuncDef("void", "main", c_ast.DeclList(), c_ast.Statements([printf]))

# print(main)