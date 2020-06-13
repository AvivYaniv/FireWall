import re
import sys
import socket
import select
import struct
from httplib import HTTPResponse
from StringIO import StringIO

from DLP import *
from sshmitm import *

# Firewall with stateful inspection
# Handels several protocols over TCP:
#    FTP
#    HTTP
#
# Interacts with kernell module firewall
# 
# Inspired by: 
#    https://gist.githubusercontent.com/deibit/3526082/raw/9994684f2c33749750b2218186b5c5fec664dae3/proxy.py

# Define Section
CONNECTION_ESTABLISHMENT_TIMEOUT_SECONDS                        = 25

# Sysfs Section
CLASS_NAME                                                      = "fw"
DEVICE_NAME_CONN_TAB                                            = "conn_tab"
SYSFS_PATH_PREFIX                                               = "/sys/class/"

# Device Section
DEVICE_PREFIX                                                   = "/dev/"

# Connection Table Char Device Section
FW_DEVICE_NAME_CONNECTION_TABLE                                 = "conn_tab"
DEVICE_CONNECTION_TABLE_ACTION_CONNECTION_TABLE_SIZE            = "conn_tab_size"
CONNECTION_TABLE_DEVICE                                         = DEVICE_PREFIX + FW_DEVICE_NAME_CONNECTION_TABLE

# Connection Table Dev Format      
CONNECTION_TABLE_DEV_ITEM_SEPERATOR                             = "\n"
CONNECTION_TABLE_DEV_FIELD_SEPERATOR                            = " "

# Connection Talbe Sysfs Section
SYSFS_CONNECTION_TABLE_PATH                                     = SYSFS_PATH_PREFIX + CLASS_NAME + "/" + FW_DEVICE_NAME_CONNECTION_TABLE + "/"
SYSFS_CONNECTION_TABLE_ATTRIBUTE_CONNECTION_TABLE_SIZE_PATH     = SYSFS_CONNECTION_TABLE_PATH + DEVICE_CONNECTION_TABLE_ACTION_CONNECTION_TABLE_SIZE

# Protocols
class PROTOCOLS:
    PROTOCOL_CONNECTION_TCP                                     = 6
    PROTOCOL_CONNECTION_FTP                                     = 7
    PROTOCOL_CONNECTION_HTTP                                    = 8

# Messages
class EXIT_CODES:
    EXIT_SUCCESS                                                = 0
    EXIT_INITIALIZE_SERVER_FAILED                               = 1
    EXIT_USER_ACTION                                            = 2
    EXIT_ERROR                                                  = 3 

class MESSAGES:
    INITIALIZE_FIREWALL_SERVER_BEGIN                            = 'Initialize firewall server started!'
    INITIALIZE_FIREWALL_SERVER_ENDED                            = 'Initialize firewall server ended!'
    BIND_SERVER_TO_HOST_FRMT                                    = 'Bind server to host {0}:{1}'
    ACCEPTED_CLIENT_FRMT                                        = 'Accepted connection with client {0}'
    CONNECT_CLIENT_FRMT                                         = 'Creating connection with client (\'{0}\', {1})'
    CLOSING_CONNECTION_WITH_CLIENT_FRMT                         = 'Closing connection with client {0}'
    USER_ACTION_EXIT                                            = 'User action exit (Control + C)'
    PEER_DISCONNECTED_FRMT                                      = 'Peer {0} disconnected'
    PEER_EXCEPTIONAL_FRMT                                       = 'Peer {0} exceptional'
    UNABLE_TO_OPEN_PROXY_PORT_TO_PEER                           = 'Unable to open proxy port to peer'
    FAILED_CONNECT_OTHER_PEER_EXCEPTION_FRMT                    = 'Failed connect to other peer: {0}'
    RECIVING_DATA_FROM_CLIENT_FRMT                              = 'Recieving data from client {0}'
    RECEIVED_DATA_FRMT                                          = 'Recived {0} bytes of data'
    RESETTING_CLIENT_FRMT                                       = 'Resetting client {0}'
    VALIDATAING_DATA_FRMT                                       = 'Validataing data (\'{0}\',{1}) -> (\'{2}\',{3})'
    PROTECTING_DATA_FRMT                                        = 'Protecting data (\'{0}\',{1}) -> (\'{2}\',{3})'
    HANDLING_RESULT_FRMT                                        = 'Handling result : {0}'
    VALIDATING_CONTENT_LENGTH                                   = 'Validating content length'
    VALIDATING_FILE_NOT_OFFICE                                  = 'Validating file not Office'
    VALIDATING_FILE_NOT_EXECUTABLE                              = 'Validating file not executable'

# Error Messages
class ERROR_MESSAGES:
    INITIALIZE_FIREWALL_SERVER_FAILED                           = 'Initialize firewall server failed: {0}'
    FAILED_READ_CONNECTION_TABLE                                = 'Failed to read connection table!'
    FAILED_ADD_TO_CONNECTION_TABLE_FRMT                         = 'Failed to add connection table; {0}'
    CLIENT_CONNECTION_NOT_FOUND_IN_CONNECTION_TABLE             = 'Client connection not found in connection table!'
    FAILED_PARSE_COMMAND_FRMT                                   = 'Failed to parse command: [{0}]'
    FAILED_TO_FORWARD_DATA                                      = 'Failed to forward data'
    ERROR_FRMT                                                  = 'Error {0}'

# Packet
class PACKET:
    MAX_SIZE                                                    = 4096 # 4 KB
    
class IP:
    """
    Return prefix of an IP, the first the digits in it's dtring form
    """
    @staticmethod    
    def getPrefix(ip):
        try:
            i=ip.rindex('.')
            return ip[0:i]
        except:
            return ""

# ips Section
class FIREWALL_IP:
    IP1                                                         = '10.1.1.3' 
    IP2                                                         = '10.1.2.3'
    allIPs                                                      = [ IP1, IP2 ]
    
    """
    Return for client IP it's matching firewall IP
    """
    @staticmethod
    def getFirewallIP(clientIP):
        clientPrefix=IP.getPrefix(clientIP)
        for firewallIp in FIREWALL_IP.allIPs:
            firewallPrefix=IP.getPrefix(firewallIp)
            if clientPrefix==firewallPrefix:
                return firewallIp

# Ports Section
class PORT:
    HTTP                                                        = 80
    FTP_DATA                                                    = 20
    FTP_COMMAND                                                 = 21
    SSH                                                         = 22
    SMTP                                                        = 25
    allInPorts                                                  = { HTTP:'HTTP', FTP_COMMAND:'FTP_COMMAND', SMTP:'SMTP' }
    allInPortsNumbers                                           = allInPorts.keys()
    allPorts                                                    = { HTTP:'HTTP', FTP_COMMAND:'FTP_COMMAND', FTP_DATA:'FTP_DATA', SMTP:'SMTP', SSH:'SSH' }
    allPortsNumbers                                             = allPorts.keys()
    
    """
    Return the string name of wellknown port numbers, or else port number as string 
    """
    @staticmethod
    def name(p):
        return PORT.allPorts[p] if (p in PORT.allPorts) else str(p)
    
class FIREWALL_PORT:
    """
    Return the maximal number of connection for specific port 
    """
    @staticmethod
    def getListenMaxConnections():
        return 10
    
    """
    Return proxy base port 
    """
    @staticmethod
    def getFirewallPort():
        return 9000
    
    """
    Return proxy input port 
    """
    @staticmethod
    def getFirewallPortIn(portByProtocol):
        return FIREWALL_PORT.getFirewallPort() + 100 + int(portByProtocol)
    
    """
    Return original port number for given firewall input port 
    """
    @staticmethod
    def getOriginalPortIn(portByProtocol):
        return portByProtocol - FIREWALL_PORT.getFirewallPortIn(0)
    
    """
    Return proxy output port 
    """
    @staticmethod
    def getFirewallPortOut(portByProtocol):        
        return FIREWALL_PORT.getFirewallPort() + 200 + int(portByProtocol)
    
    """
    Return original port number for given firewall output port 
    """
    @staticmethod
    def getOriginalPortOut(portByProtocol):
        return portByProtocol - FIREWALL_PORT.getFirewallPortOut(0)
    
    """
    Return all matching firewall ports in
    """
    @staticmethod
    def getAllFirewallPortsIn(ports):
        return [FIREWALL_PORT.getFirewallPortIn(p) for p in ports]
    
    """
    Return all matching firewall ports out
    """
    @staticmethod
    def getAllFirewallPortsOut(ports):
        return [FIREWALL_PORT.getFirewallPortOut(p) for p in ports]
               

class CIPConverter:
    """
    Converts IP from string to number
    """
    @staticmethod
    def ip2long(ip):
        packedIP = socket.inet_aton(ip)
        return struct.unpack("!L", packedIP)[0]
    
    """
    Converts IP from number to string 
    """
    @staticmethod
    def long2ip(ip):
        return socket.inet_ntoa(struct.pack('!L', int(ip)))

class CConnectionTable:
    INDEX_INITIATOR_IP    = 0
    INDEX_INITIATOR_PORT  = 1
    
    INDEX_RESPONDER_IP    = 2
    INDEX_RESPONDER_PORT  = 3
    
    INDEX_PROTOCOL        = 4
    
    INDEX_INITIATOR_STATE = 5
    INDEX_RESPONDER_STATE = 6
    
    INDEX_TIME_ADDED      = 7
    
    """
    Reads connection table
    """
    @staticmethod
    def read():
        # Openning connection table for reading
        fConnectionTable = open(CONNECTION_TABLE_DEVICE, "r")        
        # Returning connections 
        return fConnectionTable.readlines()
    
    """
    Returns whether peers match in both fields (IP && Port)
    """
    @staticmethod
    def isMatch(peerFirst, peerSecond):
        return ((long(peerFirst[0]) == long(peerSecond[0])) and 
                (int(peerFirst[1])  == int(peerSecond[1])))
    
    """
    Finds the matcing peer in connection table, or None if non existant
    """
    @staticmethod
    def findMatchingPeer(ipFirstPeer, portFirstPeer):
        # Setting first peer name
        nameFirstPeer = CIPConverter.ip2long(ipFirstPeer), portFirstPeer        
        # Fetching connection
        connectionRows = CConnectionTable.read()        
        # Going over the connections, searching for matching peer
        for connectionRow in connectionRows:  
            # Splitting row to words  
            connectionRow = connectionRow.split()
            # Fetching initiator name
            nameInitiator = connectionRow[CConnectionTable.INDEX_INITIATOR_IP], connectionRow[CConnectionTable.INDEX_INITIATOR_PORT]
            nameResponder = connectionRow[CConnectionTable.INDEX_RESPONDER_IP], connectionRow[CConnectionTable.INDEX_RESPONDER_PORT]            
            # Found match, returning second peer, the responder
            if CConnectionTable.isMatch(nameFirstPeer, nameInitiator):                          
                return nameResponder            
        # Match not found
        return None
    
    """
    Formats connection so it can be written to connection talbe
    """
    @staticmethod
    def formatConnection(ipSrc, portSrc, ipDst, portDst, protocol):
        return CONNECTION_TABLE_DEV_FIELD_SEPERATOR.join([str(ipSrc), str(portSrc), str(ipDst), str(portDst), chr(protocol)]) + CONNECTION_TABLE_DEV_ITEM_SEPERATOR
    
    """
    Adds connection to connection table
    """
    @staticmethod
    def addConnection(ipSrc, portSrc, ipDst, portDst, protocol):
        try:            
            fConnectionTable = open(CONNECTION_TABLE_DEVICE, "w")
            fConnectionTable.write(CConnectionTable.formatConnection(ipSrc, portSrc, ipDst, portDst, protocol))
            fConnectionTable.close()
        except Exception, e:
            print(ERROR_MESSAGES.FAILED_ADD_TO_CONNECTION_TABLE_FRMT.format(e))
            return False
        return True

# Classes Section 
class CProxyConnect:
    """
    Creating other peer socket to forward to
    """    
    def __init__(self):
        self.forward = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.forward.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.forward.settimeout(CONNECTION_ESTABLISHMENT_TIMEOUT_SECONDS)        

    """
    Connect proxy to server, given client details
    Finding server based on connection table
    """
    def toOtherPeer(self, client1):
        try:
            client1_host, client1_port = client1
            client2_host, client2_port = \
                CConnectionTable.findMatchingPeer(client1_host, client1_port)
            print(MESSAGES.CONNECT_CLIENT_FRMT.format(CIPConverter.long2ip(client2_host), str(client2_port)))            
            self.forward.bind((FIREWALL_IP.getFirewallIP(client1_host), client1_port))
            self.forward.connect((client2_host, int(client2_port)))
            return self.forward
        except Exception, e:
            print(MESSAGES.FAILED_CONNECT_OTHER_PEER_EXCEPTION_FRMT.format(e))            
            return False

# Based on: https://stackoverflow.com/questions/24728088/python-parse-http-response-string
class CDataToSocket():
    """
    Convert data to socket file
    """
    def __init__(self, data):
        self._file = StringIO(data)
        
    """
    Returns socket file
    """
    def makefile(self, *args, **kwargs):
        return self._file

# Inspired by: 
#    https://www.garykessler.net/library/file_sigs.html
#    https://en.wikipedia.org/wiki/List_of_file_signatures
class MAGIC_FILE_SIGNATURES:
    # Microsoft Office Files
    MICROSOFT_OFFICE_OPEN_XML           = '\x50\x4B\x03\x04\x14\x00\x06\x00'
    MICROSOFT_OFFICE_OLECF              = '\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1'    
    magicsMicrosoftOffice               = [ MICROSOFT_OFFICE_OPEN_XML, MICROSOFT_OFFICE_OLECF]
    # Executable Files
    MZ_WINDOWS_DOS_EXECUTABLE           = '\x4D\x5A'
    ELF_EXECUTABLE                      = '\x7F\x45\x4C\x46'
    MACH_O_BINARY_32                    = '\xFE\xED\xFA\xCE'
    MACH_O_BINARY_64                    = '\xFE\xED\xFA\xCF'
    DALVIK_EXECUTABLE                   = '\x64\x65\x78\x0A\x30\x33\x35\x00'
    magicsExecutable                    = [ MZ_WINDOWS_DOS_EXECUTABLE, MACH_O_BINARY_32, MACH_O_BINARY_64, DALVIK_EXECUTABLE ]     

class CValidatorFile:
    """
    Returns whether file matches magic
    """
    @staticmethod
    def isMatch(magic, data):
        # If data is insufficient to match
        if len(magic) > len(data):
            return False
        # Going over data looking it dosen't match magic 
        for i in range(len(magic)):
            if data[i] != magic[i]:
                return False
        return True
    
    """
    Returns whether file matches magics
    """
    @staticmethod
    def isFile(magics, data):        
        # Going over magics, looking for a match in file
        for magic in magics:
            if CValidatorFile.isMatch(magic, data):
                return True
        return False
    
    """
    Returns whether Office file
    """
    @staticmethod
    def isOfficeFile(data):
        print(MESSAGES.VALIDATING_FILE_NOT_OFFICE)
        return CValidatorFile.isFile(MAGIC_FILE_SIGNATURES.magicsMicrosoftOffice, data)

    """
    Returns whether file is executable 
    """
    @staticmethod
    def isExecutableFile(data):
        print(MESSAGES.VALIDATING_FILE_NOT_EXECUTABLE)
        return CValidatorFile.isFile(MAGIC_FILE_SIGNATURES.magicsExecutable, data)

class CHandlerHTTP:
    CONTENT_LENGTH_MAX                  = 2000
    
    def __init__(self):
        self.dataLeakPreventor = CDataLeakPreventor()
    
    """
    Returns whether data passed through HTTP is valid
    """
    def validate(self, data):
        return self.isValidData(data)
    
    """
    Returns whether data passed through HTTP is valid, 
    If no content-length header - block
    If Office file  greather than CHandlerHTTP.CONTENT_LENGTH_MAX - block
    Not allowing Data Leaks
    """    
    def isValidData(self, data):
        print(MESSAGES.VALIDATING_CONTENT_LENGTH)
        # Converting data to socket
        s = CDataToSocket(data)
        # Parsing socket to HTTP Response
        response = HTTPResponse(s)
        # Fetching content-length
        response.begin()
        content_length = response.getheader('Content-Length')
        # If no conetent-length in header - blocking        
        if (not content_length):            
            return False
        # DLP
        language = None
        try:
            language = self.dataLeakPreventor.detectCode(data)
            return not language
        except:
            return False
            pass
        # Reading content
        content = response.read(bytearray(CHandlerHTTP.CONTENT_LENGTH_MAX))
        return not (CValidatorFile.isOfficeFile(content) and \
                    (CHandlerHTTP.CONTENT_LENGTH_MAX < long(content_length)))

class CHandlerSMTP:
    def __init__(self):
        self.dataLeakPreventor = CDataLeakPreventor()
    
    """
    Returns whether data passed through SMTP is valid
    """    
    def validate(self, data):
        return self.isValidData(data)
    
    """
    Returns whether data passed through SMTP is valid, 
    Not allowing Data Leaks
    """
    def isValidData(self, data):
        language = None
        try:
            language = self.dataLeakPreventor.detectCode(data)
            return not language
        except:
            pass
        return False     

class CHandlerSSH:
    """
    Returns whether data passed through SSH is valid
    """
    def protectSrc(self, data):
        print("protectSrc")
        if -1 < data.find("SSH-2.0-libssh-0.6.3"):
            print("Found!!!!!!!")
            if 150 > len(data) or True:
                print("Doo!!!!!!!")
                data = data.replace("SSH-2.0-libssh-0.6.3", "SSH-2.0-libssh-0.7.6")
        return data
    
    def protectDst(self, ip, data):
        print("protectDst")
        if 0 < data.find("Ruby"):
            print("Found!!!!!!!")
            # data = data.replace("SSH-2.0-libssh-0.6.3", "SSH-2.0-libssh-0.7.6")
            print("XXXX!!!!!!!")
        return data  
            
class CConverterIP:
    """
    Converts IP from string to int
    """
    @staticmethod
    def convertStringToInt(string):
        return struct.unpack("!I", socket.inet_aton(string))[0]

    """
    Converts IP from int to string
    """
    @staticmethod
    def convertIntToString(integer):
        return socket.inet_ntoa(struct.pack("!I", integer))

class CHandlerFTP:
    def __init__(self):
        self.regexpPortCommand   = re.compile('PORT (\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3}),(\d{1,3})')
    
    """
    Handles FTP command, if it's PORT - creating new connection
    """
    def handle(self, ip, data):          
        parsedPortCommand = self.parsePortCommand(data) 
        if parsedPortCommand:            
            parsedPortCommand_IP, parsedPortCommand_Port = parsedPortCommand            
            firewall.bindFirewallToPort(parsedPortCommand_IP, parsedPortCommand_Port)       
            return CConnectionTable.addConnection(CConverterIP.convertStringToInt(ip), PORT.FTP_DATA, \
                                                  CConverterIP.convertStringToInt(parsedPortCommand_IP), parsedPortCommand_Port, \
                                                  PROTOCOLS.PROTOCOL_CONNECTION_TCP)            
        return True
    
    """
    Parsing FTP PORT command
    """
    def parsePortCommand(self, data):
        matchPortCommand    = self.regexpPortCommand.match(data)        
        if not matchPortCommand:
            print(ERROR_MESSAGES.FAILED_PARSE_COMMAND_FRMT.format(data))
            return None
        try:
            ipStringPortCommand = ".".join([matchPortCommand.group(i) for i in range(1,5)])            
            portIntPortCommand  = 256*int(matchPortCommand.group(5))+int(matchPortCommand.group(6))
            if (65535 >= portIntPortCommand) and (0 <= portIntPortCommand):
                return (ipStringPortCommand, portIntPortCommand)
        except:
            pass
        print(ERROR_MESSAGES.FAILED_PARSE_COMMAND_FRMT.format(data))            
        return None
    
    """
    Validate data passed in FTP 
    """
    def validate(self, data):
        return self.isValidContent(data)
     
    """
    Validate data passed in FTP 
    Not allowing executables
    """          
    def isValidContent(self, data):
        return not CValidatorFile.isExecutableFile(data)

class CDataHandler:
    def __init__(self):
        self.handlerFTP      =   CHandlerFTP()
        self.handlerSMTP     =   CHandlerSMTP()
        self.handlerHTTP     =   CHandlerHTTP()
        # Setting handlers
        self.handlersSrcPort = {
                                    PORT.FTP_DATA       : self.handlerFTP,      \
                                    PORT.HTTP           : self.handlerHTTP,     \
                                    PORT.SMTP           : self.handlerSMTP,              
                                }
        self.handlersDstPort = {
                                    PORT.FTP_COMMAND    : self.handlerFTP,             
                                }
    
    def handleSrcPort(self, port, data):
        if port not in self.handlersSrcPort.keys():
            return False
        else:
            return self.handlersSrcPort[port].validate(data)

    def handleDstPort(self, ip, port, data):
        if port not in self.handlersDstPort.keys():
            return False
        else:
            return self.handlersDstPort[port].handle(ip, data)            
        
    """
    Handling data
    """  
    def handleData(self, srcIp, srcPort, dstIp, dstPort, data):
        print(MESSAGES.VALIDATAING_DATA_FRMT.format(srcIp, PORT.name(srcPort), dstIp, PORT.name(dstPort)))
        # Handling data according to source port        
        bSrcPortValidations = True  if (srcPort not in self.handlersSrcPort.keys()) \
                                    else self.handleSrcPort(srcPort, data)
        bDstPortValidations = True  if (dstPort not in self.handlersDstPort.keys()) \
                                    else self.handleDstPort(dstIp, dstPort, data)
        bValidationResult = bSrcPortValidations and bDstPortValidations
        print(MESSAGES.HANDLING_RESULT_FRMT.format(bValidationResult))
        return bValidationResult

class CDataProtector:
    def __init__(self):
        self.handlerSSH      =   CHandlerSSH()
        
        # Setting handlers
        self.protectersSrcPort = {
                                    # PORT.SSH            : self.handlerSSH,
                                 }
        self.protectersDstPort = {
                                    # PORT.SSH            : self.handlerSSH,
                                 }
    
    def protectSrcPort(self, port, data):
        if port not in self.protectersSrcPort.keys():
            return False
        else:
            return self.protectersSrcPort[port].protectSrc(data)

    def protectDstPort(self, ip, port, data):
        if port not in self.protectersDstPort.keys():
            return False
        else:
            return self.protectersDstPort[port].protectDst(ip, data)            
        
    """
    Protecting data
    """  
    def protectData(self, srcIp, srcPort, dstIp, dstPort, data):
        print(MESSAGES.PROTECTING_DATA_FRMT.format(srcIp, PORT.name(srcPort), dstIp, PORT.name(dstPort)))
        # Protecting data according to source port       
        if (srcPort in self.protectersSrcPort.keys()):
            data = self.protectSrcPort(srcPort, data)
        if (dstPort in self.protectersDstPort.keys()):
            data = self.protectDstPort(dstIp, dstPort, data)
        return data

class CServer: 
    RECIVE_TIMEOUT  =   0.1
    
    """
    Recive all data from socket
    """  
    @staticmethod
    def reciveAll(socket):
        fragments = []
        try:
            socket.settimeout(CServer.RECIVE_TIMEOUT)
            while True:
                chunk = socket.recv(PACKET.MAX_SIZE)                
                # print(MESSAGES.RECEIVED_DATA_FRMT.format(len(chunk)))
                # If empty message
                # NOTE: *NOT* considering netcat empty message which is actually '\n'                                
                if not chunk:
                    break
                fragments.append(chunk)                
        except:
            pass
        return b''.join(fragments)
    
    """
    Binding server to listen ports
    """  
    def bindServerToListenPorts(self, ipIn, serverPorts):
        # Server sockets to host
        sockets = []        
        # Going over the ports and binding sockets to them
        for i in range(len(serverPorts)):
            print(MESSAGES.BIND_SERVER_TO_HOST_FRMT.format(ipIn, serverPorts[i]))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((ipIn, serverPorts[i]))
            s.listen(FIREWALL_PORT.getListenMaxConnections())
            sockets.append(s)        
        # Return server to host binded sockets for all ports 
        return sockets
       
    """
    Binding server to listen port
    """ 
    def bindServerToPort(self, ipIn, port):
        # Return server to host binded sockets for port 
        return self.bindServerToListenPorts(ipIn, [port])

class CFirewallServer(CServer):    
    """
    Initializing proxy server member variables
    """ 
    def __init__(self):
        self.m_socketsAcceptable     = []    
        self.m_socketsInputs         = []
        self.m_socketsOutputs        = []        
        self.m_socketConnections     = {}
        self.m_ips                   = FIREWALL_IP.allIPs
        self.m_ports                 = FIREWALL_PORT.getAllFirewallPortsIn(PORT.allInPortsNumbers)
        self.m_dataHandler           = CDataHandler()
        self.m_dataProtector         = CDataProtector()      
        
    # Initialize firewall server:
    #    Bind server to all ips, and for each of them to all protocols ports
    #
    # Inspired by: 
    #    https://docs.python.org/2/howto/sockets.html
    #    https://docs.python.org/2/library/socket.html
    def initialize(self):
        print(MESSAGES.INITIALIZE_FIREWALL_SERVER_BEGIN)        
        try:
            # TODO DEBUG
            createProxySSH("10.1.1.3", 9122)         
            # Binding firewall to listen on ports   
            for ip in self.m_ips:
                socketsBinded = self.bindServerToListenPorts(ip,self.m_ports)
                self.m_socketsAcceptable.extend(socketsBinded)
                # Adding to listening sockets to inputs list
                self.m_socketsInputs.extend(socketsBinded)
        except Exception as e:
            print(ERROR_MESSAGES.INITIALIZE_FIREWALL_SERVER_FAILED.format(e))
            sys.exit(EXIT_CODES.EXIT_INITIALIZE_SERVER_FAILED)            
        print(MESSAGES.INITIALIZE_FIREWALL_SERVER_ENDED)
        
    """
    Bind firewall to ports 
    """
    def bindFirewallToPort(self, clientIP, port):
        try:         
            # Binding firewall to listen on port
            print('BIND FW C {0} {1}'.format(clientIP, port))
            firewallIP = FIREWALL_IP.getFirewallIP(clientIP)     
            print('BIND FW ACTUAL {0} {1}'.format(firewallIP, port))          
            socketsBinded = self.bindServerToPort(firewallIP, port)            
            self.m_socketsAcceptable.extend(socketsBinded)
            # Adding to listening sockets to inputs list
            self.m_socketsInputs.extend(socketsBinded)
        except Exception as e:
            print(MESSAGES.UNABLE_TO_OPEN_PROXY_PORT_TO_PEER + str(e))
            pass
        
    """
    Running of proxy, handling new connections, data recive and peer reset 
    """
    def run(self):
        # Initializing socket binding to ips
        self.initialize()
        # Run and handle sockets
        while True:
            # Wating fore new connection attempts
            socketsReadable, socketsWritable, socketsExceptional = \
                select.select(self.m_socketsInputs, self.m_socketsOutputs, [])
            # If connection is exceptional
            for socket in socketsExceptional:
                print(MESSAGES.PEER_EXCEPTIONAL_FRMT.format(socket.getpeername()))
                # Closing socket
                self.removePeers(socket)
            # If connection is ready for read
            for socket in socketsReadable:
                # If new connection is being listened
                if socket in self.m_socketsAcceptable:
                    # Accepting new client
                    self.onAccept(socket)                    
                # Else, handling data
                else:
                    # Recieve data from client
                    self.onRecieve(socket)
    
    """
    Handling new socket 
    """                    
    def onAccept(self, socketToAccept):
        socketClient1ToFirewall, addressClient1ToFirewall = socketToAccept.accept()
        print(MESSAGES.ACCEPTED_CLIENT_FRMT.format(addressClient1ToFirewall))            
        socketFirewallToClient2 = CProxyConnect().toOtherPeer(addressClient1ToFirewall)
        if socketFirewallToClient2:
            self.addConnection(socketClient1ToFirewall, socketFirewallToClient2)
        else:            
            print(MESSAGES.CLOSING_CONNECTION_WITH_CLIENT_FRMT.format(addressClient1ToFirewall))
            socketClient1ToFirewall.close()
    
    """
    Handling data recive 
    """ 
    def onRecieve(self, socketClientToFirewall): 
        try:      
            print(MESSAGES.RECIVING_DATA_FROM_CLIENT_FRMT.format(socketClientToFirewall.getpeername()))
        except:
            pass        
        # Recieve data from client
        dataFromClient = self.reciveAll(socketClientToFirewall)        
        # If no data recieved - means end of connection
        if 0 == len(dataFromClient):
            # Disconnecting client
            self.onDisconnectPeers(socketClientToFirewall)
        # Else, data recived        
        else:
            # Handling recevied data
            self.handleData(socketClientToFirewall, dataFromClient)
     
    """
    Handling data and forwarding it, or resetting if no data recived 
    """       
    def handleData(self, socketClientToFirewall, dataFromClient): 
        try:
            socketFirewallToClient  = self.m_socketConnections[socketClientToFirewall]
            ipSource                = socketClientToFirewall.getpeername()[0]
            portSource              = socketClientToFirewall.getpeername()[1]
            ipDestination           = socketFirewallToClient.getpeername()[0]
            portDestination         = socketFirewallToClient.getpeername()[1]
        except:
            return
        dataFromClientSecured   = self.m_dataProtector.protectData(ipSource, portSource, ipDestination, portDestination, dataFromClient)        
        bForwardData            = self.m_dataHandler.handleData(ipSource, portSource, ipDestination, portDestination, dataFromClientSecured)
        # If should not forward data
        if not bForwardData:
            # Resetting both peers
            self.onResetPeers(socketClientToFirewall);
        # Else, forwarding data to other peer
        else:
            self.onForward(socketClientToFirewall, dataFromClientSecured)
      
    """
    Handling data forwarding 
    """   
    def onForward(self, socketClientToFirewall, data):
        try:
            # Finding socket to send to
            socketFirewallToClient = self.m_socketConnections[socketClientToFirewall]
            # If socket to sent to found
            if socketFirewallToClient:
                self.onSend(socketFirewallToClient, data)
        except Exception, e:
            print(ERROR_MESSAGES.FAILED_TO_FORWARD_DATA)
    
    """
    Handling data send 
    """ 
    def onSend(self, socketFirewallToClient, dataSend):
        dataLength = len(dataSend)        
        totalsent = 0
        while totalsent < dataLength:
            sent = socketFirewallToClient.send(dataSend[totalsent:])
            if sent == 0:
                break
            totalsent = totalsent + sent
        return totalsent        
      
    """
    Handling reset peers 
    """   
    def onResetPeers(self, socketPeer1):
        socketPeer2 = self.m_socketConnections[socketPeer1]
        self.resetClient(socketPeer1)
        if socketPeer2:
            self.resetClient(socketPeer2)
        self.removePeers(socketPeer1)
        
    """
    Disconnecting peers and removing them
    """
    def onDisconnectPeers(self, socketPeer1):
        try:        
            print(MESSAGES.PEER_DISCONNECTED_FRMT.format(socketPeer1.getpeername()))
        except:
            pass
        self.removePeers(socketPeer1)
        
    """
    Handling shutdown
    """
    def onShutdown(self, exitCode):
        # Closing all input sockets
        self.closeSocketList(self.m_socketsInputs) 
        # Closing all output sockets
        self.closeSocketList(self.m_socketsOutputs)                   
        # Exitting
        sys.exit(exitCode)
    
    """
    Handling client reset
    """
    @staticmethod    
    def resetClient(s):
        l_onoff = 1                                                                                                                                                           
        l_linger = 0                                                                                                                                                          
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', l_onoff, l_linger))
        print(MESSAGES.RESETTING_CLIENT_FRMT.format(s.getpeername()))        
       
    """
    Closing all sockets in list
    """ 
    def closeSocketList(self, socketList):
        while 0 != len(socketList):
            self.removePeers(socketList[0]) 
     
    """
    Adding new connection
    """    
    def addConnection(self, socketPeer1, socketPeer2):
        self.m_socketsInputs.append(socketPeer1)
        self.m_socketsInputs.append(socketPeer2)
        self.m_socketConnections[socketPeer1] = socketPeer2
        self.m_socketConnections[socketPeer2] = socketPeer1
      
    """
    Deleting connection
    """      
    def delConnection(self, socketPeer1, socketPeer2):
        if socketPeer2:
            # close the connection with client
            socketPeer2.close()
        if socketPeer1:
            # close the connection with remote server
            socketPeer1.close()    
        # delete both objects from m_socketConnections dict
        if socketPeer2 in self.m_socketConnections:
            del self.m_socketConnections[socketPeer2]            
        if socketPeer1 in self.m_socketConnections:
            del self.m_socketConnections[socketPeer1] 
    
    """
    Removing peers
    """ 
    def removePeers(self, socketPeer1):
        if socketPeer1 in self.m_socketsInputs:        
            self.m_socketsInputs.remove(socketPeer1)        
        socketPeer2 = self.m_socketConnections.get(socketPeer1)
        # remove objects from m_socketsInputs
        if socketPeer2:
            self.m_socketsInputs.remove(socketPeer2)
        # Delete peer connection        
        self.delConnection(socketPeer1, socketPeer2)

firewall = CFirewallServer()

# For debug of protocols
# firewall.bindFirewallToPort('10.1.1.1', 3000)

if __name__ == '__main__':               
        try:
            firewall.run()
        except KeyboardInterrupt:
            print(MESSAGES.USER_ACTION_EXIT)
            # Shutting down firewall
            firewall.onShutdown(EXIT_CODES.EXIT_USER_ACTION)
        except Exception, e:            
            print(ERROR_MESSAGES.ERROR_FRMT.format(e))
            # Shutting down firewall
            firewall.onShutdown(EXIT_CODES.EXIT_ERROR)
        