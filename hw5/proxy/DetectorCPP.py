import re

from RegExp     import *
from Detector   import *
from DetectorC  import *

class CLanguageCPP:
    # Comments
    SINGLE_LINE_COMMENT_PREFIX      =   "//"
    MULTI_LINE_COMMENT_PREFIX       =   "/*"
    MULTI_LINE_COMMENT_SUFFIX       =   "*/"
    
    # Tokens
    TOKENS                          =   [ ':' ] + CLanguageC.tokens
    
    class CRegExpCPP:
        # Command
        COMMAND_SEPERATOR       =       ";"
        # Macro
        NOT_MACRO_PREFIX        =       "[^#]"
        # Token Section
        POINTER_DELIMETER       =       "\*"
        FIELD_DELIMETER         =       "\."
        ARROW_DELIMETER         =       "->"
        COMPILED_STATEMENTS     =       CLanguageC.statements
        COMPILED_ACTIONS        =       CLanguageC.actions
    
    class CKeyWordsCPP:        
        IOS_KEYWORDS            =       [ "io_errc", "streamoff", "streampos", "streamsize", "wstreampos", "boolalpha", "showbase", "showpoint", "showpos", "skipws", "unitbuf", "uppercase", "noboolalpha", "noshowbase", "noshowpoint", "noshowpos", "noskipws", "nounitbuf", "nouppercase", "dec", "hex", "oct", "fixed", "scientific", "internal", "left", "right" ]
        IOSTREAM_KEYWORDS       =       [ "cin", "cout", "cerr", "clog", "wcin", "wcout", "wcerr", "wclog" ]
        KEYWORDS                =       [ 
                                            # Common
                                            "std",              \
                                            # new
                                            "new", "delete"
                                        ] + IOS_KEYWORDS + IOSTREAM_KEYWORDS + CLanguageC.keywords 
        FUNCTIONS               =       [ 
                                            # stl
                                            "assign(", "at(", "back(", "before_begin(", "begin(", "capacity(", "cbefore_begin(", "cbegin(", "cend(", "clear(", "crbegin(", "crend(", "data(", "emplace(", "emplace_after(", "emplace_back(", "emplace_front(", "empty(", "end(", "erase(", "erase_after(", "front(", "get_allocator(", "insert(", "insert_after(", "max_size(", "merge(", "pop_back(", "pop_front(", "push_back(", "push_front(", "rbegin(", "remove(", "remove_if(", "rend(", "reserve(", "resize(", "reverse(", "shrink_to_fit(", "size(", "sort(", "splice(", "splice_after(", "swap(", "unique(",   \
                                            # locale
                                            "isspace(", "isprint(", "iscntrl(", "isupper(", "islower(", "isalpha(", "isdigit(", "ispunct(", "isxdigit(", "isalnum(", "isgraph(", "isblank(",                                                                                                                                                                                                                                                                                                                                                                                                                            \
                                            # string
                                            "stoi(", "stol(", "stoul(", "stoll(", "stoull(", "stof(", "stod(", "stold(", "to_string(", "to_wstring(",                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
                                        ] + CRegExp.makeFunctions(IOS_KEYWORDS) + CRegExp.makeFunctions(IOSTREAM_KEYWORDS) + CLanguageC.functions
        DATA_STRUCTURES         =       [
                                            # Data Structues
                                            "vector<", "list<", "deque<", "forward_list<", "queue<", "priority_queue<", "stack<", "set<", "multiset<", "map<", "multimap<"
                                        ]
        LIBRARIES               =       [   
                                            "ios", "iostream", "string" 
                                        ] + CLanguageC.libraries
    
    # Static Analyse
    keywords            =   CKeyWordsCPP.KEYWORDS
    libraries           =   CKeyWordsCPP.LIBRARIES
    functions           =   CKeyWordsCPP.FUNCTIONS
    statements          =   CRegExpCPP.COMPILED_STATEMENTS
    actions             =   CRegExpCPP.COMPILED_ACTIONS    
    tokens              =   TOKENS
    data_structures     =   CKeyWordsCPP.DATA_STRUCTURES
    commnad_seperator   =   CRegExpCPP.COMMAND_SEPERATOR
    case_sensitivity    =   True

class CDetectorCPP(CDetectorBlockCurlyBrackets):
    DETECTOR_NAME                   =   "C++"
    
    LANGUAGE                        =   CLanguageCPP()
    
    # Ctor
    def __init__(self):
        super(CDetectorCPP, self).__init__(CDetectorCPP.LANGUAGE)

        