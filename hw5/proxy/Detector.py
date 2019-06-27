import re
import math

from DEBUG          import *
from StaticAnalysis import *

class SANITY:
    CODE                            =       1
    SMALL_CODE                      =       2
    DOCUMENTATION                   =       3
    
    @staticmethod
    def getName(x):
        if      x == SANITY.CODE:
            return "CODE"
        elif    x == SANITY.SMALL_CODE:
            return "SMALL_CODE"
        elif    x == SANITY.DOCUMENTATION:
            return "DOCUMENTATION"
        return "None"

class BLOCK_ENDING_TYPE:
    END_OF_FILE                     =       1
    NEW_BLOCK                       =       2
    END_OF_BLOCK                    =       3

class CDetector(object):
    # Name
    DETECTOR_NAME                   =      '<Unnamed Detector>'
    # Language
    LANGUAGE_PROFILE                =       None
    
    # Ctor
    def __init__(self, language):
        self.LANGUAGE_PROFILE = language
        self.staticAnalyser = CStaticAnaliser(language.tokens, 
                                              language.functions, 
                                              language.keywords,
                                              language.libraries, 
                                              language.statements, 
                                              language.actions, 
                                              language.data_structures,
                                              language.commnad_seperator,
                                              language.case_sensitivity)
    # Dictoinary Key Section #
    def __hash__(self):
        return hash(str(self.DETECTOR_NAME))
    
    def __eq__(self, other):
        return (self.DETECTOR_NAME) == (other.DETECTOR_NAME)
    
    # Methods Section #
    # Detector Section #
    def getName(self):
        return self.DETECTOR_NAME
    
    # Comment Section #
    def getSingleLineCommentPrefix(self):
        return self.LANGUAGE_PROFILE.SINGLE_LINE_COMMENT_PREFIX
    
    def getMultiLineCommentPrefix(self):
        return self.LANGUAGE_PROFILE.MULTI_LINE_COMMENT_PREFIX
    
    def getMultiLineCommentSuffix(self):
        return self.LANGUAGE_PROFILE.MULTI_LINE_COMMENT_SUFFIX
    
    def stripData(self, prefix, suffix, appender, data):
        # If either prefix or suffix are not given, return data
        if (not prefix) or (not suffix):
            return data        
        # Finding prefix index
        indexOfPrefix = data.find(prefix)        
        # If prefix is not in text, return data     
        if -1 == indexOfPrefix:
            return data
        # Filtering
        fragments = []
        suffixLength = len(suffix)                
        # Going over data and filtering between prefix and suffix
        while -1 != indexOfPrefix:
            # Finding first occurance of suffix after prefix
            indexOfSuffix = data.find(suffix, indexOfPrefix)            
            # If suffix not found - ending loop
            if -1 == indexOfSuffix:
                break            
            if 0 != indexOfPrefix:
                # Appending all valid till prefix 
                fragments.append(data[:(indexOfPrefix-1)])            
            # Cutting data after suffix
            data = data[(indexOfSuffix + suffixLength):]            
            # Finding prefix in data
            indexOfPrefix = data.find(prefix)  
        fragments.append(data)              
        # Joining valid fragments
        return appender.join(fragments)
    
    def stripSingleLineComments(self, data):
        return self.stripData(self.getSingleLineCommentPrefix(),    \
                              "\n",                                 \
                              "\n",                                 \
                              data)

    def stripMultiLineComments(self, data):        
        return self.stripData(self.getMultiLineCommentPrefix(),     \
                              self.getMultiLineCommentSuffix(),     \
                              "",                                   \
                              data)

    def stripComments(self, data):
        stripped = data        
        # Important; we first strip the multi line, to avoid cases in which single line token inside
        if self.getMultiLineCommentPrefix() and self.getMultiLineCommentSuffix():
            stripped = self.stripMultiLineComments(stripped)
        stripped = self.stripSingleLineComments(stripped)
        return stripped

    # Find is matching language profile
    def isMatching(self, data):                
        # If no statements
        if not self.staticAnalyser.getStatementsCount(data):                             
            # If no functions and no statements - it's not a match
            if not self.staticAnalyser.getFunctionsCount(data):            
                return False
        # There are both statements and functions - seems fishy 
        return True
    
    # Dynamic Analyse Section
    def getAnlysisRank(self, anlysisResult):
        LIBRARY_WEIGHT          =   5
        FUNCTION_WEIGHT         =   5
        STATEMENT_WEIGHT        =   5
        DATA_STRUCTURE_WEIGHT   =   7
        ACTION_WEIGHT           =   2
        WORD_WEIGHT             =   1        
        rank = 0        
        rank += LIBRARY_WEIGHT          *   anlysisResult.librariesCount
        rank += FUNCTION_WEIGHT         *   anlysisResult.functionsCount
        rank += STATEMENT_WEIGHT        *   anlysisResult.statementsCount
        rank += ACTION_WEIGHT           *   anlysisResult.actionsCount
        rank += ACTION_WEIGHT           *   anlysisResult.actionsCount
        rank += DATA_STRUCTURE_WEIGHT   *   anlysisResult.dataStructuresCount        
        rank += WORD_WEIGHT             *   anlysisResult.keywordsCount
        if DEBUG.DEBUG_PRINT_BLOCK_RANKS:
            print(anlysisResult)
            print(DEBUG.BLCOK_RANK_PRINT_FRMT.format(str(rank)))           
        return rank
    
    def anomalyTests(self, anlysisResult, MINIMUM_COMMANDS_FOR_DETECTION):
        FUNCTIONS_COMMANDS_MAX_RATIO    =   10
        # Calculating function commands ratio
        functionCommandsRatio   =   anlysisResult.functionsCount if (0 >= anlysisResult.commandsCount) \
                                    else (anlysisResult.functionsCount / anlysisResult.commandsCount)        
        # If way more functions than code lines - it's probably documentation
        if functionCommandsRatio > FUNCTIONS_COMMANDS_MAX_RATIO:
            return SANITY.DOCUMENTATION
        # If small amount of commands
        if anlysisResult.commandsCount < MINIMUM_COMMANDS_FOR_DETECTION:
            return SANITY.SMALL_CODE
        # No anomaly detected
        return SANITY.CODE
        
    def getRank(self, data, MINIMUM_COMMANDS_FOR_DETECTION):
        rank                =   0
        nestedBlocks        =   self.getNestedBlock(data)
        resultAccumulated   =   CStaticAnaliserResult()   
        # Going over nested block, analysing them and accumulating their ranks
        for nb in nestedBlocks:
            nesting_level, block = nb
            if block:
                block_result = self.staticAnalyser.runAnalysis(block)            
                resultAccumulated += block_result
                rank += self.getAnlysisRank(block_result) * nesting_level        
        # Running anomaly tests - if fails, decreses rank
        anomalyTestResult = self.anomalyTests(resultAccumulated, MINIMUM_COMMANDS_FOR_DETECTION)
        if anomalyTestResult != SANITY.CODE:
            rank = rank**0.5  
            if DEBUG.DEBUG_PRINT_ANOMALY:
                print(SANITY.getName(anomalyTestResult))
        if DEBUG.DEBUG_PRINT_TOTAL_RANKS:
            print(DEBUG.DETECTOR_RANK_PRINT_FRMT.format(self.getName(), rank))      
        # Return data rank
        return rank
    
    # Dynamic Analyse Section
    def getNestedBlock(self, data):
        debug_print     = ""
        nesting_level   = 1
        nestedBlocks    = []
        data = self.prepareDataBlocks(data)
        ending_type, ending_index = self.getBlockEndingDetails(data, nesting_level)
        # As long there is data - seperate to block according to nesting level
        while data:
            debug_print += DEBUG.BLOCK_FILE_FRMT.format(str(nesting_level))
            # Cut current block
            block = data[:ending_index]
            # Appending block and it's nesting level to list
            nestedBlocks.append((nesting_level, block))  
            # Cutting data after ending 
            data = data[(ending_index):]  
            # TODO DEBUG
            debug_print += block
            # TODO DEBUG
            if BLOCK_ENDING_TYPE.NEW_BLOCK == ending_type:
                nesting_level += 1            
            elif BLOCK_ENDING_TYPE.END_OF_BLOCK == ending_type:
                nesting_level = max(1, nesting_level - 1)
            # Advancing to next block    
            ending_type, ending_index = self.getBlockEndingDetails(data, nesting_level)
        if DEBUG.DEBUG_WRITE_FILES:
            DEBUG.writeFileContent(DEBUG.BLOCKS_FILE_NAME_FRMT.format(self.getName()), debug_print)
        # Return nested blocks
        return nestedBlocks

class CDetectorBlockIdents(CDetector):
    # Block
    BLOCK_PREFIX    =   "\t"
    
    def prepareDataBlocks(self, data):
        data = re.sub("    ", self.BLOCK_PREFIX, data)
        linesTrimmed = []
        for l in data.splitlines():
            trimmed = l.rstrip()
            if trimmed:
                linesTrimmed.append(trimmed)
        return "\n".join(linesTrimmed)
    
    # Methods Section
    def getBlockEndingDetails(self, data, nesting_level):
        index                   = 0
        new_block_begins_index  = -1
        this_block_ends_index   = -1
        for l in data.splitlines():
            search_prefixes = re.search(r'[^' + self.BLOCK_PREFIX + ']', l)            
            line_nesting_level = 1 if not search_prefixes else max(search_prefixes.start()+1, 1)
            if line_nesting_level < nesting_level:
                this_block_ends_index = index
                break
            elif line_nesting_level > nesting_level:
                new_block_begins_index = index
                break
            # Because of '\n' we add another one
            index += len(l) + 1        
        # If block dosen't end and new block dosen't begins - continue till end
        if (-1 == new_block_begins_index) and (-1 == this_block_ends_index):
            return (BLOCK_ENDING_TYPE.END_OF_FILE, len(data))
        # If we got here at least one of the indexes is positive
        # Calculating one index AFTER the block indicator (to exclude brackets)  
        new_block_begins_skipped_index  = new_block_begins_index
        this_block_ends_skipped_index   = this_block_ends_index
        # If no new block begins, but this block ends
        if (-1 == new_block_begins_index):
            return (BLOCK_ENDING_TYPE.END_OF_BLOCK, this_block_ends_skipped_index)
        # If this block dosen't end, but new block begins
        if (-1 == this_block_ends_index):
            return (BLOCK_ENDING_TYPE.NEW_BLOCK, new_block_begins_skipped_index)
        # If we got here both indexes are positive
        # If new block begins
        if new_block_begins_skipped_index < this_block_ends_skipped_index:
            return (BLOCK_ENDING_TYPE.NEW_BLOCK, new_block_begins_skipped_index)
        # Else this block ends
        else:
            return (BLOCK_ENDING_TYPE.END_OF_BLOCK, this_block_ends_skipped_index) 

class CDetectorBlockCurlyBrackets(CDetector):
    # Block
    BLOCK_PREFIX    =   "{"
    BLOCK_SUFFIX    =   "}"
    
    # Methods Section
    def prepareDataBlocks(self, data):
        return data
    
    def getBlockEndingDetails(self, data, nesting_level):
        new_block_begins_index      = data.find(self.BLOCK_PREFIX)
        this_block_ends_index       = data.find(self.BLOCK_SUFFIX)
        # If block dosen't end and new block dosen't begins - continue till end
        if (-1 == new_block_begins_index) and (-1 == this_block_ends_index):
            return (BLOCK_ENDING_TYPE.END_OF_FILE, len(data))
        # If we got here at least one of the indexes is positive
        # Calculating one index AFTER the block indicator (to exclude brackets)  
        new_block_begins_skipped_index  = new_block_begins_index    + 1
        this_block_ends_skipped_index   = this_block_ends_index     + 1
        # If no new block begins, but this block ends
        if (-1 == new_block_begins_index):
            return (BLOCK_ENDING_TYPE.END_OF_BLOCK, this_block_ends_skipped_index)
        # If this block dosen't end, but new block begins
        if (-1 == this_block_ends_index):
            return (BLOCK_ENDING_TYPE.NEW_BLOCK, new_block_begins_skipped_index)
        # If we got here both indexes are positive
        # If new block begins
        if new_block_begins_index < this_block_ends_index:
            return (BLOCK_ENDING_TYPE.NEW_BLOCK, new_block_begins_skipped_index)
        # Else this block ends
        else:
            return (BLOCK_ENDING_TYPE.END_OF_BLOCK, this_block_ends_skipped_index) 
