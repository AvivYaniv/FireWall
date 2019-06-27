import re

from RegExp     import *
from Detector   import *

class CLanguageC:
    # Comments
    SINGLE_LINE_COMMENT_PREFIX      =   "//"
    MULTI_LINE_COMMENT_PREFIX       =   "/*"
    MULTI_LINE_COMMENT_SUFFIX       =   "*/"
    
    # Tokens
    TOKENS                          = [ 
                                        ';',                    \
                                        '{', '}',               \
                                        '[', ']',               \
                                        '(', ')',               \
                                        '<', '>',               \
                                        '&', '|',               \
                                        '+', '-', '*', '/',     \
                                        '_',                    \
                                      ]
    
    class CRegExpC:
        # Command
        COMMAND_SEPERATOR       =       ";"
        # Macro
        NOT_MACRO_PREFIX        =       "[^#]"
        # Token Section
        POINTER_DELIMETER       =       "\*"
        FIELD_DELIMETER         =       "\."
        ARROW_DELIMETER         =       "->"    
        # Block Section
        BLOCK                   =       CRegExp.CURLY_BRACKETS
        DO_BLOCK                =       "do"        + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        STRUCT_BLOCK            =       "struct"    + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        # Code Lines Section
        CODE_LINE               =       CRegExp.SPACES + CRegExp.CONTENT + COMMAND_SEPERATOR
        # Conditions Section
        IF_CONDITION            =       NOT_MACRO_PREFIX + "if"      + CRegExp.SPACES + CRegExp.ROUND_BRACKETS
        ELSE_CONDITION          =       NOT_MACRO_PREFIX + "else"    + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        ELSE_IF_CONDITION       =       NOT_MACRO_PREFIX + "else if" + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        # Loops Section
        FOR_LOOP                =       "for"   + CRegExp.SPACES + CRegExp.ROUND_BRACKETS 
        WHILE_LOOP              =       "while" + CRegExp.SPACES + CRegExp.ROUND_BRACKETS    
        # Actions Section
        FIELD_ACTION            =       POINTER_DELIMETER   + CRegExp.CONTENT   + FIELD_DELIMETER
        ARROW_ACTION            =       ARROW_DELIMETER
        # Complied Statements Section
        COMPILED_BLOCK          =       re.compile(BLOCK,           re.MULTILINE)     
        COMPILED_IF_CONDITION   =       re.compile(IF_CONDITION)
        COMPILED_ELSE_CONDITION =       re.compile(ELSE_CONDITION)
        COMPILED_ELIF_CONDITION =       re.compile(ELSE_IF_CONDITION)        
        COMPILED_FOR_LOOP       =       re.compile(FOR_LOOP)
        COMPILED_WHILE_LOOP     =       re.compile(WHILE_LOOP)    
        COMPILED_STRUCT_BLOCK   =       re.compile(STRUCT_BLOCK)
        COMPILED_DO_BLOCK       =       re.compile(DO_BLOCK)    
        COMPILED_STATEMENTS     =       [ 
                                            COMPILED_IF_CONDITION, COMPILED_ELSE_CONDITION, COMPILED_ELIF_CONDITION,    \
                                            COMPILED_FOR_LOOP, COMPILED_WHILE_LOOP,                                     \
                                            COMPILED_DO_BLOCK, COMPILED_STRUCT_BLOCK                                    \
                                        ]
        # Compiled Actions Section
        COMPILED_FIELD_ACTION   =       re.compile(FIELD_ACTION)
        COMPILED_ARROW_ACTION   =       re.compile(ARROW_ACTION)
        COMPILED_ACTIONS        =       [
                                            COMPILED_FIELD_ACTION,                              \
                                            COMPILED_ARROW_ACTION,                              \
                                        ]
    
    class CKeyWordsC:
        KEYWORDS                =       [ 
                                            "NULL", "auto", "else", "long", "switch", "break", "enum", "register", "typedef", "case", "extern", "return", "union", "char", "float", "short", "unsigned", "const", "signed", "void", "continue", "goto", "volatile", "default", "static", "int", "Packed", "double" 
                                        ] 
        FUNCTIONS               =       [ 
                                            # Common
                                            "sizeof(", "main(", "#if", "#ifdef", "#define", "#undef", "#include",                                                                                                                                                                                                                                                                                                                                   \
                                            # stdio.h
                                            "fclose(", "feof(", "ferror(", "fflush(", "fgetpos(", "fopen(", "fread(", "fseek(", "fsetpos(", "ftell(", "fwrite(", "remove(", "rename(", "rewind(", "setbuf(", "setvbuf(", "fprintf(", "printf(", "sprintf(", "vfprintf(", "vprintf(", "vsprintf(", "fscanf(", "scanf(", "sscanf(", "fgetc(", "fgets(", "fputc(", "fputs(", "getc(", "getchar(", "gets(", "putc(", "putchar(", "puts(", "ungetc(",    \
                                            # stdlib.h
                                            "atof(", "atoi(", "atol(", "strtod(", "strtol(", "strtoul(", "calloc(", "free(", "malloc(", "realloc(", "abort(", "atexit(", "exit(", "getenv(", "bsearch(", "qsort(", "abs(", "div(", "rand(", "srand(",                                                                                                                                                                                               \
                                            # string.h
                                            "memchr(", "memcmp(", "memcpy(", "memmove(", "memset(", "strcat(", "strncat(", "strchr(", "strcmp(", "strncmp(", "strcoll(", "strcpy(", "strncpy(", "strcspn(", "strerror(", "strlen(", "strpbrk(", "strrchr(", "strspn(", "strstr(", "strtok(",                                                                                                                                                        \
                                            # math.h
                                            "acos(", "asin(", "atan(", "atan2(", "cos(", "cosh(", "sin(", "sinh(", "tanh(", "exp(", "frexp(", "ldexp(", "log(", "log10(", "pow(", "sqrt(", "ceil(", "fabs(", "floor(",                                                                                                                                                                                                                              \
                                            # Kernel Memory Allocation 
                                            "kmalloc(", "kmalloc_array(", "kcalloc(", "kzalloc(", "kzalloc_node(", "kmem_cache_alloc(", "kmem_cache_alloc_node(", "kmem_cache_free(", "kfree(", "ksize(",                                                                                                                                                                                                                                            \
                                        ]
        DATA_STRUCTURES         =       []
        LIBRARIES               =       [   
                                            "stdio.h", "stdlib.h", "string.h", "math.h", "kernel.h"  
                                        ]
    
    # Static Analyse
    keywords            =   CKeyWordsC.KEYWORDS
    libraries           =   CKeyWordsC.LIBRARIES
    functions           =   CKeyWordsC.FUNCTIONS
    statements          =   CRegExpC.COMPILED_STATEMENTS
    actions             =   CRegExpC.COMPILED_ACTIONS    
    tokens              =   TOKENS
    data_structures     =   CKeyWordsC.DATA_STRUCTURES
    commnad_seperator   =   CRegExpC.COMMAND_SEPERATOR
    case_sensitivity    =   True

class CDetectorC(CDetectorBlockCurlyBrackets):
    DETECTOR_NAME                   =   "C"
    
    LANGUAGE                        =   CLanguageC()
    
    # Ctor
    def __init__(self):
        super(CDetectorC, self).__init__(CDetectorC.LANGUAGE)

        