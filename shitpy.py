import argparse
import ast
from random import choice, randint
from typing import Any


# =============== OBFLIB PART ===============
def setparents(obj: ast.AST):
    for parent in ast.walk(obj):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent  # type: ignore


def baseN(alph: str | list[str], num) -> str:
    if num == 0:
        return alph[0]
    result = []
    base = len(alph)
    while num > 0:
        num, rem = divmod(num, base)
        result.append(alph[rem])
    return "".join(reversed(result))


class NameGen:
    def __init__(self, prefix: str = "_", key: int = randint(1, 255555)) -> None:
        self.ptr: int = 0
        self.prefix: str = prefix
        self.post: str = ""
        self.key: int = key
        self.alph: str | list[str] = "OОΟ"
        self.used: set[str] = set(builtins)

    def next(self) -> str:
        while (
            name := self.prefix + baseN(self.alph, self.ptr ^ self.key) + self.post
        ) in self.used:
            self.ptr += 1

        self.used.add(name)
        return name


builtins = dir(__import__("builtins"))
builtins = list(filter(lambda x: not x.startswith("__"), builtins))
builtins = list(filter(lambda x: x not in ("super",), builtins))
builtins.extend(["__import__", "__build_class__"])


def get_ctx(node: ast.AST):
    if hasattr(node, "parent"):
        if isinstance(
            node.parent,  # type: ignore
            (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            return node.parent  # type: ignore
        return get_ctx(node.parent)  # type: ignore


# =============== OBFLIB PART ===============


name = NameGen("_", randint(0, 255))


def strobf(s: str, skey: int) -> list[int]:
    ns = []
    for c in s[::-1]:
        ns.append(~(ord(c) ^ skey))
        ns.append(randint(1, 10000) ^ skey)
    return ns


def intobf(i: int, k1: int, offs: int) -> int:
    return ((~i) ^ k1) << offs


def destr(arg):
    x = arg[::2]
    (result, (tmp)) = ("", [])
    for part in x:
        tmp += [~part ^ 106]
        tmp[-1] = chr(tmp[-1])
        result += tmp[-1]
    return result[::-1]


class Const(ast.NodeTransformer):
    def __init__(self, names: str, skey, namei: str, ikey, ioffs) -> None:
        self.names = names
        self.namei = namei
        self.ikey = ikey
        self.ioffs = ioffs
        self.skey = skey

    def visit_Constant(self, node: ast.Constant) -> Any:
        if node.parent.__class__ is not ast.MatchValue:  # type: ignore
            if node.value.__class__ is str:
                r = (
                    ast.parse(f"{self.names}({strobf(node.value, self.skey)})")  # type: ignore
                    .body[0]
                    .value  # type: ignore
                )

                if node.parent.__class__ is ast.JoinedStr:  # type: ignore
                    return ast.FormattedValue(r, -1)
                return r

            elif node.value.__class__ is int:
                r = (
                    ast.parse(
                        f"{self.namei}({intobf(node.value, self.ikey, self.ioffs)})"  # type: ignore
                    )
                    .body[0]
                    .value  # type: ignore
                )

                if node.parent.__class__ is ast.JoinedStr:  # type: ignore
                    return ast.FormattedValue(r, -1)

                return r

        return node


class Name2Eval(ast.NodeTransformer):
    def __init__(self, nameval: str) -> None:
        self.fnameval = nameval

    def visit_Name(self, node: ast.Name) -> Any:
        if node.ctx.__class__ is not ast.Store and node.id in builtins:
            return ast.Call(
                ast.Name(self.fnameval, ast.Load()), [ast.Constant(node.id)], []
            )
        return node


class UnarySpam(ast.NodeTransformer):
    def visit_Constant(self, node: ast.Constant) -> Any:

        if not isinstance(node.value, int):
            return node

        if isinstance(
            node.parent,  # type: ignore
            (ast.UnaryOp, ast.Call, ast.Attribute, ast.Subscript, ast.FormattedValue),
        ):
            return node

        pares = [
            (ast.USub, ast.USub),
            (ast.Invert, ast.Invert),
        ]
        for _ in range(randint(1, 4)):
            p = choice(pares)
            node = ast.UnaryOp(p[1](), ast.UnaryOp(p[0](), node))  # type: ignore
        return node


class Lambder(ast.NodeTransformer):
    def obj2lambdac(self, node: ast.expr):
        r = self.generic_visit(node)  # type: ignore
        if get_ctx(node).__class__ is ast.ClassDef:
            return r

        if type(node.parent) is not ast.MatchValue:  # type: ignore
            if hasattr(node, "ctx") and type(node.ctx) is ast.Store:  # type: ignore
                return r

            size = randint(0, 3)
            names = [name.next() for _ in range(size)]
            ll = ast.Lambda(
                ast.arguments([], [ast.arg(n) for n in names], None, [], [], None, []),
                ast.Subscript(
                    ast.Tuple([*[ast.Name(n, ast.Load()) for n in names], r]),  # type: ignore
                    ast.Constant(size),
                ),
            )
            return ast.Call(ll, [ast.Constant(name.next()) for _ in range(size)], [])
        return r

    visit_Name = visit_Constant = obj2lambdac


def _hex(x: int):
    return (h := f"{x:x}").zfill(len(h) + len(h) % 2)


def taber(s: str, t: int):
    tt = f"\n{' ' * 4 * t}"
    return tt + tt.join(s.splitlines())


def catsploit(s: str):
    ns = ""
    for ss in s.splitlines():
        ns += ss + "#\r#tg#########:###@######paket#########ls#######\n" if ss else "\n"

    return ns


def compiler(s: bytes):
    code = ast.parse(s)

    tabs = randint(2, 17)

    _ifromby = name.next()
    _byhtomh = name.next()

    _funcstr = name.next()
    _funcint = name.next()
    _funcbytes = name.next()
    _nameval = name.next()

    skey = randint(1, 1000)
    ikey = randint(1, 1000)
    ioffs = randint(5, 10)

    _junk = name.next()

    _stmp1 = name.next()
    _stmp2 = name.next()
    _stmp3 = name.next()
    _stmp4 = name.next()
    _stmp5 = name.next()

    _itmp1 = name.next()
    loader = f"""# shitpy
exec('')                                                                                                                                                                                                                                                                         if ((({_ifromby}:=((((int.from_bytes))))) or True) and (({_byhtomh}:=bytes.fromhex))) else((((((((((((((((((((-+-++-~0xFAFAFAFAFAFAFAFAFFFFFFFFFFFFFFF))))))))))))))))))))
{_junk}                =    0x0000000000000000000000010239102                                                                                                                                                            if ((({_nameval}:=(((((((((((((((((((((((((((((((((((((eval))))))))))))))))))))))))))))))))))))))))else(((([[[[[[[[[[[[[[[[()][0x000]]]]]]]]]]]]]]]]))))
def {_funcstr}({_stmp4}):
    {_stmp5} = {_stmp4}[::([(0b10&((((~((+-+-+-+-(1))))))))])[0o00000000000000000000000]]
    ({_stmp3},({_stmp2})) =(      (''                   ,[]))
    for    {_stmp1}                 in   {_stmp5}         :
        {_junk} if {_junk} else 0o123121
        {_stmp2}+=[[((((~~~~~~~~~~~~~{_stmp1}))^                 0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000{hex(skey)[2:].upper()}))]][0+1-1]
        {_stmp2}[-(100-(   ([{_ifromby}] )[-~~+~~-+0x000000])({_byhtomh}(        "63")))]=chr((({_stmp2}[-+-+-1])))
        {_stmp3}         +={_stmp2}                                                           [-(1_0_0-{_ifromby}({_byhtomh}("63")))]
    return {_stmp3}[  :          :-( 0o144-(((( ({_ifromby})  )((  (({_byhtomh}("36"[::-+-+-+-+---1])))))))))]
def {_funcint}({_itmp1}):
    return 0                                                                                                                         +((~~(~({_itmp1})>>(~~~{bin(~ioffs)}))^{_ifromby}(({_byhtomh}('''0000000000000000{_hex(ikey).upper()}''')))))
{"\n" * randint(100, 200)}"""

    code = Name2Eval(_nameval).visit(code)

    for _ in range(randint(1, 3)):
        setparents(code)
        code = Const(_funcstr, skey, _funcint, ikey, ioffs).visit(code)

    setparents(code)
    code = Lambder().visit(code)

    setparents(code)
    code = UnarySpam().visit(code)

    for i in range(tabs):
        loader += f"if 1:\n{(i + 1) * ' ' * 4}"

    return (loader + catsploit(taber(ast.unparse(code), tabs))).encode()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShitPy obfuscation")
    parser.add_argument("file", type=str, help="Target file")
    parser.add_argument("-o", type=str, help="Output file")

    args = parser.parse_args()

    file = args.file

    with open(file, "rb") as f:
        code = f.read()

    output = compiler(code)
    if not output:
        print("# cant be compiled")
        quit()

    if args.o:
        with open(args.o, "wb") as f:
            f.write(output)
            print("# saved!")
    else:
        print(output.decode(errors="ignore"))
