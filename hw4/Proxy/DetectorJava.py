import re

from RegExp     import *
from Detector   import *

class CLanguageJava:
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
    
    class CRegExpJava:
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
        WHILE_LOOP              =       "while"     + CRegExp.SPACES + CRegExp.ROUND_BRACKETS    
        # Actions Section
        FIELD_ACTION            =       CRegExp.CONTENT   + FIELD_DELIMETER + CRegExp.CONTENT        
        # Complied Statements Section
        COMPILED_BLOCK          =       re.compile(BLOCK,           re.MULTILINE)     
        COMPILED_IF_CONDITION   =       re.compile(IF_CONDITION)
        COMPILED_ELSE_CONDITION =       re.compile(ELSE_CONDITION)
        COMPILED_ELSE_CONDITION =       re.compile(ELSE_IF_CONDITION)
        COMPILED_FOR_LOOP       =       re.compile(FOR_LOOP)
        COMPILED_WHILE_LOOP     =       re.compile(WHILE_LOOP)    
        COMPILED_ENUM_BLOCK     =       re.compile(ENUM_BLOCK)
        COMPILED_DO_BLOCK       =       re.compile(DO_BLOCK)    
        COMPILED_STATEMENTS     =       [ 
                                            COMPILED_IF_CONDITION, COMPILED_ELSE_CONDITION, COMPILED_ELSE_CONDITION,    \
                                            COMPILED_FOR_LOOP, COMPILED_WHILE_LOOP,                                     \
                                            COMPILED_DO_BLOCK, COMPILED_ENUM_BLOCK                                      \
                                        ]
        # Compiled Actions Section
        COMPILED_FIELD_ACTION   =       re.compile(FIELD_ACTION)        
        COMPILED_ACTIONS        =       [
                                            COMPILED_FIELD_ACTION                                         
                                        ]
    
    class CKeyWordsJava:
        KEYWORDS                =       [ 
                                            "abstract", "assert", "boolean", "break", "byte", "case", "catch", "char", "class", "const", "default", "double", "else", "enum", "extends", "false", "final", "finally", "float", "goto", "implements", "import", "instanceof", "int", "interface", "long", "native", "new", "null", "package", "private", "protected", "public", "return", "short", "static", "strictfp", "super", "switch", "synchronized", "this", "throw", "throws", "transient", "true", "try", "void", "volatile", "continue" 
                                        ] 
        FUNCTIONS               =       [ 
                                            # Common
                                            "main(", "toString(", "getClass(", "equals(", "hashCode(", "clone(", "notify(", "notifyAll(",                                                                                                                                                                                                                                                                                                                                                                                       \
                                            # System
                                            "println(", "print(", "arraycopy(", "clearProperty(", "console(", "currentTimeMillis(", "exit(", "gc(", "getenv(", "getenv(", "getProperties(", "getProperty(", "getProperty(", "getSecurityManager(", "identityHashCode(", "inheritedChannel(", "lineSeparator(", "load(", "loadLibrary(", "mapLibraryName(", "nanoTime(", "runFinalization(", "runFinalizersOnExit(", "setErr(", "setIn(", "setOut(", "setProperties(", "setProperty(", "setSecurityManager(",                    \
                                            # java.util
                                            "add(", "addAll(", "clear(", "compute(", "computeIfAbsent(", "computeIfPresent(", "contains(", "containsKey(", "containsValue(", "containsAll(", "entrySet(", "forEach(", "get(", "getOrDefault(", "isEmpty(", "iterator(", "remove(", "removeAll(", "retainAll(", "size(", "toArray(", "binarySearch(", "copyOf(", "copyOfRange(", "deepEquals(", "deepHashCode(", "fill(", "sort(", "merge(", "put(", "putAll(", "putIfAbsent(", "replace(", "replaceAll(", "values(",            \
                                            # java.io 
                                            "accept(", "flush(", "readBoolean(", "readByte(", "readChar(", "readDouble(", "readExternal(", "readFloat(", "readFully(", "readFully(", "readInt(", "readLine(", "readLong(", "readShort(", "readUnsignedByte(", "readUnsignedShort(", "readUTF(", "skipBytes(", "write(", "write(", "write(", "writeBoolean(", "writeByte(", "writeBytes(", "writeChar(", "writeChars(", "writeDouble(", "writeExternal(", "writeFloat(", "writeInt(", "writeLong(", "writeShort(", "writeUTF(",  \
                                            # java.text
                                            "getAllAttributeKeys(", "getAttributes(", "getRunLimit(", "getRunStart(", "current(", "first(", "getBeginIndex(", "getEndIndex(", "getIndex(", "last(", "getEndIndex(", "next(", "previous(", "setIndex(", "format(", "formatToCharacterIterator(", "parseObject(",                                                                                                                                                                                                                 \
                                            # java.util.regex
                                            "start(", "end(", "group(", "groupCount(", "appendReplacement(", "appendTail(", "find(", "groupCount(", "hasAnchoringBounds(", "hasTransparentBounds(", "hitEnd(", "lookingAt(", "matches(", "pattern(", "quoteReplacement(", "regionEnd(", "regionStart(", "replaceAll(", "replaceFirst(", "requireEnd(", "toMatchResult(", "useAnchoringBounds(", "usePattern(", "useTransparentBounds",                                                                                                                                                                                                                                                                                                                                                                                 
                                        ]
        DATA_STRUCTURES         =       [
                                            # Data Structures
                                            "ArrayList<", "HashMap(", "TreeSet(", "IdentityHashMap(", "LinkedHashMap(", "WeakHashMap(", "TreeMap(", "HashSet(", "LinkedList("
                                        ]
        LIBRARIES               =       [   
                                            "java.util", "java.io", "java.text", "java.util.regex", "java.awt"   
                                        ]
    
    # Static Analyse
    keywords            =   CKeyWordsJava.KEYWORDS
    libraries           =   CKeyWordsJava.LIBRARIES
    functions           =   CKeyWordsJava.FUNCTIONS
    statements          =   CRegExpJava.COMPILED_STATEMENTS
    actions             =   CRegExpJava.COMPILED_ACTIONS    
    tokens              =   TOKENS
    data_structures     =   CKeyWordsJava.DATA_STRUCTURES
    commnad_seperator   =   CRegExpJava.COMMAND_SEPERATOR
    case_sensitivity    =   True

class CDetectorJava(CDetectorBlockCurlyBrackets):
    DETECTOR_NAME                   =   "Java"
    
    LANGUAGE                        =   CLanguageJava()
    
    # Ctor
    def __init__(self):
        super(CDetectorJava, self).__init__(CDetectorJava.LANGUAGE)
  