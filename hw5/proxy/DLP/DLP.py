import re
import time
import string
import operator

from RegExp         import *
from DetectorC      import *
from DetectorCS     import *
from DetectorCPP    import *
from DetectorJava   import *
from DetectorPython import *
from DEBUG          import *
    
#### Main Section ####
class CDataLeakPreventor:
    # Configuration
    MINIMUM_COMMANDS_FOR_DETECTION  =       5
    DETECTION_THRESHOLD             =       100
    
    DETECTORS                       =       [ CDetectorC(), CDetectorCS(), CDetectorCPP(), CDetectorJava(), CDetectorPython() ]
    # DETECTORS                       =       [ CDetectorPython() ]
    
    # Methods Section #
    def detectCode(self, data):
        possibleLanguagesToStrippedData = {}     
        # Statics analysing to detect language
        for detector in CDataLeakPreventor.DETECTORS:
            strippedComments = detector.stripComments(data)
            if DEBUG.DEBUG_WRITE_FILES:
                DEBUG.writeFileContent(DEBUG.STRIPPED_FILE_NAME_FRMT.format(detector.getName()), strippedComments)                     
            if detector.isMatching(strippedComments):
                possibleLanguagesToStrippedData[detector] = strippedComments                
        # If no language detected based on static analysis 
        if not possibleLanguagesToStrippedData:
            return None        
        # Ranking language probabilities 
        languagesProbabilitiesUnsorted = {}
        for d in possibleLanguagesToStrippedData:
            strippedData                        =   possibleLanguagesToStrippedData[d]                        
            languageRank                        =   d.getRank(strippedData, CDataLeakPreventor.MINIMUM_COMMANDS_FOR_DETECTION)
            languagesProbabilitiesUnsorted[d]   =   languageRank            
        # Get maximal rank language
        maximalRankLanguage = max(languagesProbabilitiesUnsorted.iteritems(), key=operator.itemgetter(1))        
        # If maximum rank dosen't exceed threshold - no language detected 
        if CDataLeakPreventor.DETECTION_THRESHOLD > maximalRankLanguage[1]:
            return None        
        # Returning name of detected language
        return maximalRankLanguage[0].getName()
    
def main():
    tic = int(round(time.time() * 1000))
    
    dlpLeakPreventor = CDataLeakPreventor()
    
    data = DEBUG.readFileContent(DEBUG.CODE_FILE_NAME)
    
    print("Found: " + str(dlpLeakPreventor.detectCode(data)))
    
    toc = int(round(time.time() * 1000))
    
    sec = (toc - tic) / 1000.0
    
    print("Done in " + str(sec))

if  __name__ =='__main__':
    main()

