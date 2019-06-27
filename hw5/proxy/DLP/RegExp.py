class CRegExp:
    CONTENT                 =       "(.*?)"
    ALPHA_NUMERIC_CONTENT   =       "[a-zA-Z0-9]"
    SPACES                  =       "[\s]*"    
    # Round Brackets
    ROUND_BRACKETS_PREFIX   =       "\("
    ROUND_BRACKETS_SUFFFIX  =       "\)"    
    ROUND_BRACKETS          =       ROUND_BRACKETS_PREFIX + CONTENT + ROUND_BRACKETS_SUFFFIX
    # Curly Brackets
    CURLY_BRACKETS_PREFIX   =       "\{"
    CURLY_BRACKETS_SUFFFIX  =       "\}"
    CURLY_BRACKETS          =       CURLY_BRACKETS_PREFIX + CONTENT + CURLY_BRACKETS_SUFFFIX
    
    @staticmethod
    def makeFunctions(l):
        return [(i + "(") for i in l]