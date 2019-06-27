class DEBUG:
    DEBUG_PRINT                     =   True
    if DEBUG_PRINT:
        DEBUG_PRINT_TOTAL_RANKS     =   False
        DEBUG_PRINT_BLOCK_RANKS     =   False
        DEBUG_PRINT_ANLYSIS         =   False
        DEBUG_PRINT_ANOMALY         =   True
        DEBUG_WRITE_FILES           =   False
    
    REGEXP_ANLYSIS_PRINT_FRMT       =   "RegExp    [{0} = {1}]"
    WORD_ANLYSIS_PRINT_FRMT         =   "Word      [{0} = {1}]"
    TOKEN_ANLYSIS_PRINT_FRMT        =   "Token     [{0} = {1}]"
    
    BLCOK_RANK_PRINT_FRMT           =   "Block rank={0}"
    DETECTOR_RANK_PRINT_FRMT        =   "Detector {0} rank={1}"
    
    BLOCK_FILE_FRMT                 =   "="*10 + " BLOCK {0} " + "="*10 + "\n"
    
    CODE_FILE_NAME                  =   "code.txt"
    STRIPPED_FILE_NAME_FRMT         =   "stripped{0}.txt"
    BLOCKS_FILE_NAME_FRMT           =   "blocks{0}.txt"
    
    @staticmethod
    def readFileContent(fileName):
        return open(fileName, "r").read() 
    
    @staticmethod
    def writeFileContent(fileName, data):
        return open(fileName, "w+").write(data) 