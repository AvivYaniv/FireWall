import re

from RegExp     import *
from Detector   import *

class CLanguageCS:
    # Comments
    SINGLE_LINE_COMMENT_PREFIX      =   "//"
    MULTI_LINE_COMMENT_PREFIX       =   "/*"
    MULTI_LINE_COMMENT_SUFFIX       =   "*/"
    
    # Block
    BLOCK_PREFIX                    =   "{"
    BLOCK_SUFFIX                    =   "}"
    
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
    
    class CRegExpCS:
        # Command
        COMMAND_SEPERATOR       =       ";"
        # Token Section        
        FIELD_DELIMETER         =       "\."   
        # Block Section
        BLOCK                   =       CRegExp.CURLY_BRACKETS
        DO_BLOCK                =       "do"        + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        ENUM_BLOCK              =       "enum"      + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        # Code Lines Section
        CODE_LINE               =       CRegExp.SPACES + CRegExp.CONTENT + COMMAND_SEPERATOR
        # Conditions Section
        IF_CONDITION            =       "if"        + CRegExp.SPACES + CRegExp.ROUND_BRACKETS
        ELSE_CONDITION          =       "else"      + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        ELSE_IF_CONDITION       =       "else if"   + CRegExp.SPACES + CRegExp.CURLY_BRACKETS
        # Loops Section
        FOR_LOOP                =       "for"       + CRegExp.SPACES + CRegExp.ROUND_BRACKETS
        FOREACH_LOOP            =       "foreach"   + CRegExp.SPACES + CRegExp.ROUND_BRACKETS 
        WHILE_LOOP              =       "while"     + CRegExp.SPACES + CRegExp.ROUND_BRACKETS    
        # Actions Section
        FIELD_ACTION            =       CRegExp.CONTENT   + FIELD_DELIMETER + CRegExp.CONTENT        
        # Complied Statements Section
        COMPILED_BLOCK          =       re.compile(BLOCK)     
        COMPILED_IF_CONDITION   =       re.compile(IF_CONDITION)
        COMPILED_ELSE_CONDITION =       re.compile(ELSE_CONDITION)
        COMPILED_ELIF_CONDITION =       re.compile(ELSE_IF_CONDITION)        
        COMPILED_FOR_LOOP       =       re.compile(FOR_LOOP)
        COMPILED_FOREACH_LOOP   =       re.compile(FOREACH_LOOP)        
        COMPILED_WHILE_LOOP     =       re.compile(WHILE_LOOP)    
        COMPILED_ENUM_BLOCK     =       re.compile(ENUM_BLOCK)
        COMPILED_DO_BLOCK       =       re.compile(DO_BLOCK)    
        COMPILED_STATEMENTS     =       [ 
                                            COMPILED_IF_CONDITION, COMPILED_ELSE_CONDITION, COMPILED_ELIF_CONDITION,    \
                                            COMPILED_FOR_LOOP, COMPILED_FOREACH_LOOP, COMPILED_WHILE_LOOP,              \
                                            COMPILED_DO_BLOCK, COMPILED_ENUM_BLOCK                                      \
                                        ]
        # Compiled Actions Section
        COMPILED_FIELD_ACTION   =       re.compile(FIELD_ACTION)        
        COMPILED_ACTIONS        =       [
                                            COMPILED_FIELD_ACTION                                         
                                        ]
    
    class CKeyWordsCS:
        KEYWORDS                =       [ 
                                            "abstract", "base", "bool", "break", "byte", "case", "catch", "char", "checked", "class", "const", "continue", "decimal", "default", "delegate", "double", "enum", "explicit", "extern", "false", "finally", "float", "goto", "implicit", "int", "interface", "internal", "lock", "long", "namespace", "new", "null", "object", "operator", "override", "params", "private", "protected", "public", "readonly", "ref", "return", "sbyte", "sealed", "short", "sizeof", "stackalloc", "static", "string", "struct", "switch", "this", "throw", "true", "try", "typeof", "uint", "ulong", "unchecked", "unsafe", "ushort", "using", "using static", "virtual", "void", "volatile" 
                                        ] 
        FUNCTIONS               =       [ 
                                            # Common
                                            "Main(", "ToString(", "Clone(", "ToObject(", "CompateTo(", "Equals(", "GetHashCode(", "GetName(", "GetNames(", "GetType(", "GetTypeCode(", "GetUnderlyingType(", "GetValues(", "HasFlag(", "IsDefined(", "Parse(",                                                                                                                                                                                                                                                                                                                                                                      \
                                            # Array
                                            "AsReadOnly<", "BinarySearch(", "BinarySearch<", "Clear(", "ConstrainedCopy(", "ConvertAll<TInput,TOutpu", "Copy(", "CopyTo(", "CreateInstance(", "Empty<", "Equals(", "Exists<", "Find<", "FindAll<", "FindIndex<", "FindLast<", "FindLastIndex<", "ForEach<", "GetEnumerator(", "GetHashCode(", "GetLength(", "GetLongLength(", "GetLowerBound(", "GetType(", "GetUpperBound(", "GetValue(", "IndexOf(", "IndexOf<", "Initialize(", "LastIndexOf(", "LastIndexOf<", "MemberwiseClone(", "Resize<", "Reverse(", "SetValue(", "Sort(", "Sort<", "Sort<TKey,TValue>(", "TrueForAll<",    \
                                            # Console 
                                            "Beep(", "Clear(", "MoveBufferArea(", "OpenStandardError(", "OpenStandardInput(", "OpenStandardOutput(", "Read(", "ReadKey(", "ReadLine(", "ResetColor(", "SetBufferSize(", "SetCursorPosition(", "SetError(", "SetIn(", "SetOut(", "SetWindowPosition(", "SetWindowSize(", "Write(", "WriteLine(",                                                                                                                                                                                                                                                                                     \
                                            # ICollection, IList, IDictionary
                                            "Contains(", "Add(", "Remove(", "Clear(", "IsReadOnly(", "IndexOf(", "Insert(", "RemoveAt(", "GetEnumerator(", "AsParallel(", "Cast<", "OfType<", "AsQueryable(",                                                                                                                                                                                                                                                                                                                                                                                                                       
                                        ]
        DATA_STRUCTURES         =       [
                                            # Data Structures
                                            "ArrayList(", "List<", "LinkedList<", "Dictionary<", "HashSet<", "KeyValuePair<", "Queue<", "SortedDictionary<", "SortedList<", "SoretdSet<", "Stack<", "SynchronizedCollection<", "SynchronizedKeyedCollection<", "SynchronizedReadOnlyCollection<",
                                        ]
        LIBRARIES               =       [   
                                            "System", "Collections"   
                                        ]
    
    # Static Analyse
    keywords            =   CKeyWordsCS.KEYWORDS
    libraries           =   CKeyWordsCS.LIBRARIES
    functions           =   CKeyWordsCS.FUNCTIONS
    statements          =   CRegExpCS.COMPILED_STATEMENTS
    actions             =   CRegExpCS.COMPILED_ACTIONS    
    tokens              =   TOKENS
    data_structures     =   CKeyWordsCS.DATA_STRUCTURES
    commnad_seperator   =   CRegExpCS.COMMAND_SEPERATOR
    case_sensitivity    =   True

class CDetectorCS(CDetectorBlockCurlyBrackets):
    DETECTOR_NAME                   =   "C#"
    
    LANGUAGE                        =   CLanguageCS()
    
    # Ctor
    def __init__(self):
        super(CDetectorCS, self).__init__(CDetectorCS.LANGUAGE)
  