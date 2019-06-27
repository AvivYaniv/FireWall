from DEBUG import *

class CStaticAnaliserResult:
    # Ctor
    def __init__(self, tokensCount=0, tokensTotal=0, keywordsCount=0, wordsTotal=0, librariesCount=0, functionsCount=0, statementsCount=0, actionsCount=0, dataStructuresCount=0, commandsCount=0):        
        self.tokensCount            =   tokensCount    
        self.tokensTotal            =   tokensTotal    
        self.keywordsCount          =   keywordsCount 
        self.librariesCount         =   librariesCount 
        self.wordsTotal             =   wordsTotal     
        self.functionsCount         =   functionsCount  
        self.statementsCount        =   statementsCount
        self.actionsCount           =   actionsCount        
        self.dataStructuresCount    =   dataStructuresCount   
        self.commandsCount          =   commandsCount
    
    def __add__(self, other):
        self.tokensCount            +=   other.tokensCount    
        self.tokensTotal            +=   other.tokensTotal    
        self.keywordsCount          +=   other.keywordsCount 
        self.librariesCount         +=   other.librariesCount 
        self.wordsTotal             +=   other.wordsTotal     
        self.functionsCount         +=   other.functionsCount  
        self.statementsCount        +=   other.statementsCount
        self.actionsCount           +=   other.actionsCount 
        self.dataStructuresCount    +=   other.dataStructuresCount  
        self.commandsCount          +=   other.commandsCount
        return self
    
    def __str__(self):
        return "librariesCount         =    " + str(self.librariesCount)        + "\n" +    \
               "functionsCount         =    " + str(self.functionsCount)        + "\n" +    \
               "statementsCount        =    " + str(self.statementsCount)       + "\n" +    \
               "actionsCount           =    " + str(self.actionsCount)          + "\n" +    \
               "dataStructuresCount    =    " + str(self.dataStructuresCount)   + "\n" +    \
               "keywordsCount          =    " + str(self.keywordsCount)       
    
class CStaticAnaliser:
    # Chars
    commnad_seperator               =       ''
    tokens                          =       []
    # Words
    functions                       =       []
    keywords                        =       []  
    # RegExps
    statements                      =       []
    actions                         =       []
    data_structures                 =       []
    
    # Ctor
    def __init__(self, tokens, functions, keywords, libraries, statements, actions, data_structures, commnad_seperator, case_sensitivity):
        self.tokens             =   tokens
        self.functions          =   functions
        self.keywords           =   keywords
        self.libraries          =   libraries
        self.statements         =   statements
        self.actions            =   actions
        self.data_structures    =   data_structures        
        self.commnad_seperator  =   commnad_seperator
        self.case_sensitivity   =   case_sensitivity        
    
    # Static Analyse Section #
    def getTokens(self):
        return self.tokens
    
    def getKeyWords(self):
        return self.keywords

    def getLibraries(self):
        return self.libraries
    
    def getFunctions(self):
        return self.functions
    
    def getStatements(self):
        return self.statements
    
    def getActions(self):
        return self.actions
    
    def getDataStructures(self):
        return self.data_structures
    
    def getCommandSeperator(self):
        return self.commnad_seperator
    
    @staticmethod
    def getTokensCount(data, tokens):        
        totalTokensCount = 0.0                
        # Counting keywords in data
        for t in tokens:            
            tokenCount = data.count(t)
            totalTokensCount += tokenCount
            if DEBUG.DEBUG_PRINT_ANLYSIS:
                if 0 < tokenCount:
                    print(DEBUG.TOKEN_ANLYSIS_PRINT_FRMT.format(t, str(tokenCount)))                                
        # Return ratio of tokens from total chars
        return totalTokensCount
    
    @staticmethod
    def getWordsCount(data, words, case_sensitive=False):
        totalWordsCount = 0.0
        # If case-INsensitivity
        if not case_sensitive:
            data = data.upper()
        # Counting keywords in data
        for w in words:
            # If case-INsensitivity
            if not case_sensitive:
                w = w.upper()
            wordCount = data.count(w)
            totalWordsCount += wordCount
            if DEBUG.DEBUG_PRINT_ANLYSIS:
                if 0 < wordCount:
                    print(DEBUG.WORD_ANLYSIS_PRINT_FRMT.format(w, str(wordCount)))        
        return totalWordsCount
        
    @staticmethod
    def getRegExpCount(data, compiled_regexps):
        totalRegexpCount = 0
        # Counting keywords in data
        for reg_complied in compiled_regexps:
            regexpCount = len(reg_complied.findall(data))
            totalRegexpCount += regexpCount
            if DEBUG.DEBUG_PRINT_ANLYSIS:
                if 0 < regexpCount:
                    print(DEBUG.REGEXP_ANLYSIS_PRINT_FRMT.format(reg_complied.pattern, str(regexpCount)))                     
        # Return RegExp total count
        return totalRegexpCount
    
    @staticmethod
    def exludeItemsFromList(list, exlude_from_list):
        exluded = []
        for x in list:
            if x not in exlude_from_list:
                exluded.append(x)
        return exluded
        
    def getStatementsCount(self, data):
        return CStaticAnaliser.getRegExpCount(data, self.getStatements())

    def getKeywordsCount(self, data):
        return CStaticAnaliser.getWordsCount(data, self.getKeyWords(), self.case_sensitivity)

    def getLibrariesCount(self, data):
        return CStaticAnaliser.getWordsCount(data, self.getLibraries(), self.case_sensitivity)
    
    def getFunctionsCount(self, data):
        return CStaticAnaliser.getWordsCount(data, self.getFunctions(), self.case_sensitivity)
    
    def getActionsCount(self, data):
        return CStaticAnaliser.getRegExpCount(data, self.getActions())

    def getDataStructuresCount(self, data):
        return CStaticAnaliser.getWordsCount(data, self.getDataStructures(), self.case_sensitivity)
    
    def getCommandsCount(self, data):
        return data.count(self.getCommandSeperator())
    
    def runAnalysis(self, data):
        # Tokens
        tokensCount                     =       self.getTokensCount(data, self.getTokens())
        tokensTotal                     =       len(data)    
        # KeyWords
        keywordsCount                   =       self.getKeywordsCount(data)
        wordsTotal                      =       len(self.exludeItemsFromList(data.split(), self.getTokens()))
        # Libraries
        librariesCount                  =       self.getLibrariesCount(data)
        # Functions                    
        functionsCount                  =       self.getFunctionsCount(data)        
        # Statements
        statementsCount                 =       self.getStatementsCount(data)
        # Actions
        actionsCount                    =       self.getActionsCount(data)
        # Data Structures
        dataStructuresCount             =       self.getDataStructuresCount(data)
        # Command
        commandsCount                   =       self.getCommandsCount(data)
        # Return result
        return CStaticAnaliserResult(tokensCount, tokensTotal, keywordsCount, wordsTotal, librariesCount, functionsCount, statementsCount, actionsCount, dataStructuresCount, commandsCount)
    