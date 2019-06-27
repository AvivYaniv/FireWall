import re

from RegExp     import *
from Detector   import *

class CLanguagePython:
    # Comments
    SINGLE_LINE_COMMENT_PREFIX      =   "#"
    MULTI_LINE_COMMENT_PREFIX       =   ""
    MULTI_LINE_COMMENT_SUFFIX       =   ""
    
    # Tokens
    TOKENS                          = [ 
                                        ':',                    \
                                        '{', '}',               \
                                        '[', ']',               \
                                        '(', ')',               \
                                        '<', '>',               \
                                        '&', '|',               \
                                        '+', '-', '*', '/',     \
                                        '_',                    \
                                      ]
    
    class CRegExpPython:
        # Command
        COMMAND_SEPERATOR       =       "\n"        
        # Token Section        
        FIELD_DELIMETER         =       "\."
        # Code Lines Section
        CODE_LINE               =       CRegExp.SPACES + CRegExp.CONTENT + COMMAND_SEPERATOR
        STATEMENT_END           =       "\:"
        # Conditions Section
        IF_CONDITION            =       "if"    + CRegExp.SPACES + CRegExp.CONTENT + STATEMENT_END
        ELSE_CONDITION          =       "else"  + CRegExp.SPACES + CRegExp.CONTENT + STATEMENT_END
        ELIF_CONDITION          =       "elif"  + CRegExp.SPACES + CRegExp.CONTENT + STATEMENT_END 
        # Loops Section
        FOR_LOOP                =       "for"   + CRegExp.SPACES + CRegExp.CONTENT + STATEMENT_END  
        WHILE_LOOP              =       "while" + CRegExp.SPACES + CRegExp.CONTENT + STATEMENT_END    
        # Actions Section
        FIELD_ACTION            =       CRegExp.ALPHA_NUMERIC_CONTENT   +   FIELD_DELIMETER +   CRegExp.ALPHA_NUMERIC_CONTENT        
        # Complied Statements Section
        COMPILED_IF_CONDITION   =       re.compile(IF_CONDITION)
        COMPILED_ELSE_CONDITION =       re.compile(ELSE_CONDITION)
        COMPILED_ELIF_CONDITION =       re.compile(ELIF_CONDITION)        
        COMPILED_FOR_LOOP       =       re.compile(FOR_LOOP)
        COMPILED_WHILE_LOOP     =       re.compile(WHILE_LOOP)
        COMPILED_STATEMENTS     =       [ 
                                            COMPILED_IF_CONDITION, COMPILED_ELSE_CONDITION, COMPILED_ELIF_CONDITION,    \
                                            COMPILED_FOR_LOOP, COMPILED_WHILE_LOOP,                                                         
                                        ]
        # Compiled Actions Section
        COMPILED_FIELD_ACTION   =       re.compile(FIELD_ACTION)        
        COMPILED_ACTIONS        =       [
                                            COMPILED_FIELD_ACTION,
                                        ]
    
    class CKeyWordsPython:
        KEYWORDS                =       [ 
                                            "assert", "break", "class", "continue", "def", "del", "except", "False", "finally", "from", "global", "import", "lambda", "None", "nonlocal", "pass", "raise", "return", "True", "try", "yield" 
                                        ] 
        FUNCTIONS               =       [ 
                                            # Common
                                            "main(", "import ", "abs(", "divmod(", "input(", "open(", "staticmethod(", "all(", "enumerate(", "int(", "ord(", "str(", "any(", "eval(", "isinstance(", "pow(", "sum(", "basestring(", "execfile(", "issubclass(", "print(", "super(", "bin(", "file(", "iter(", "property(", "tuple(", "bool(", "filter(", "len(", "range(", "type(", "bytearray(", "float(", "list(", "raw_input(", "unichr(", "callable(", "format(", "locals(", "reduce(", "unicode(", "chr(", "frozenset(", "long(", "reload(", "vars(", "classmethod(", "getattr(", "map(", "repr(", "xrange(", "cmp(", "globals(", "max(", "reversed(", "zip(", "compile(", "hasattr(", "memoryview(", "round(", "__import__(", "complex(", "hash(", "min(", "set(", "delattr(", "help(", "next(", "setattr(", "dict(", "hex(", "object(", "slice(", "dir(", "id(", "oct(", "sorted(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      \
                                            # Class
                                            "__init__", "__str__", "__iter__", "__contains__", "__len__", "__setitem__", "__eq__", "__ne__", "__reversed__", "__hash__", "__call__", "__le__", "__lt__", "__gt__", "__ge__", "__and__", "__or__", "__sub__", "__xor__",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         \
                                            # re
                                            "compile(", "escape(", "findall(", "finditer(", "match(", "purge(", "search(", "split(", "sub(", "subn(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           \
                                            # sys
                                            "call_tracing(", "displayhook(", "emencoding(", "excepthook(", "exc_clear(", "exc_info(", "exit(", "getcheckinterval(", "getdefaultencoding(", "getdlopenflags(", "getprofile(", "getrecursionlimit(", "getrefcount(", "getsizeof(", "gettrace(", "getwindowsversion(", "platform.startswith(", "setcheckinterval(", "setdefaultencoding(", "setdlopenflags(", "setprofile(", "setrecursionlimit(", "settrace(", "settscdump(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     \
                                            # collections
                                            "namedtuple(", "Counter(", "elements(", "append(", "appendleft(", "clear(", "count(", "elements(", "extend(", "extendleft(", "pop(", "popleft(", "remove(", "reverse(", "rotate(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  \
                                            # StringIO
                                            "StringIO(", "getvalue(", "close(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 \
                                            # os 
                                            "abort(", "access(", "chdir(", "chflags(", "chmod(", "chown(", "chroot(", "close(", "closerange(", "confstr(", "ctermid(", "dup(", "dup2(", "execl(", "execle(", "execlp(", "execlpe(", "execv(", "execve(", "execvp(", "execvpe(", "fchdir(", "fchmod(", "fchown(", "fdatasync(", "fdopen(", "fork(", "forkpty(", "fpathconf(", "fstat(", "fstatvfs(", "fsync(", "ftruncate(", "getcwd(", "getcwdu(", "getegid(", "getenv(", "geteuid(", "getgid(", "getgroups(", "getloadavg(", "getlogin(", "getpgid(", "getpgrp(", "getpid(", "getppid(", "getresgid(", "getresuid(", "getsid(", "getuid(", "initgroups(", "isatty(", "kill(", "killpg(", "lchflags(", "lchmod(", "lchown(", "link(", "listdir(", "lseek(", "lstat(", "major(", "makedev(", "makedirs(", "minor(", "mkdir(", "mkfifo(", "mknod(", "nice(", "open(", "openpty(", "pathconf(", "pipe(", "plock(", "popen(", "popen2(", "popen3(", "popen4(", "putenv(", "read(", "readlink(", "remove(", "removedirs(", "rename(", "renames(", "rmdir(", "setegid(", "seteuid(", "setgid(", "setgroups(", "setpgid(", "setpgrp(", "setregid(", "setresgid(", "setresuid(", "setreuid(", "setsid(", "setuid(", "spawnl(", "spawnle(", "spawnlp(", "spawnlpe(", "spawnv(", "spawnve(", "spawnvp(", "spawnvpe(", "stat(", "statvfs(", "stat_float_times(", "strerror(", "symlink(", "sysconf(", "system(", "tcgetpgrp(", "tcsetpgrp(", "tempnam(", "times(", "tmpfile(", "tmpnam(", "ttyname(", "umask(", "uname(", "unlink(", "unsetenv(", "urandom(", "utime(", "wait(", "wait3(", "wait4(", "waitpid(", "walk(", "WCOREDUMP(", "WEXITSTATUS(", "WIFCONTINUED(", "WIFEXITED(", "WIFSIGNALED(", "WIFSTOPPED(", "write(", "WSTOPSIG(", "WTERMSIG("   \
                                        ]
        DATA_STRUCTURES         =       [
                                            # Data Structures
                                            "list(", "dict(", "set(", "frozenset("
                                        ]
        LIBRARIES               =       [   
                                            "import re", "import sys", "import collections", "import StringIO", "import os",    \
                                            "import *"
                                        ]
    
    # Static Analyse
    keywords            =   CKeyWordsPython.KEYWORDS
    libraries           =   CKeyWordsPython.LIBRARIES
    functions           =   CKeyWordsPython.FUNCTIONS
    statements          =   CRegExpPython.COMPILED_STATEMENTS
    actions             =   CRegExpPython.COMPILED_ACTIONS    
    tokens              =   TOKENS
    data_structures     =   CKeyWordsPython.DATA_STRUCTURES
    commnad_seperator   =   CRegExpPython.COMMAND_SEPERATOR
    case_sensitivity    =   True

class CDetectorPython(CDetectorBlockIdents):
    DETECTOR_NAME                   =   "Python"
    
    LANGUAGE                        =   CLanguagePython()
    
    # Ctor
    def __init__(self):
        super(CDetectorPython, self).__init__(CDetectorPython.LANGUAGE)
   