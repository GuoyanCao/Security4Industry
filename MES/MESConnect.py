import socket
import time
import os
import ssl
import pprint

config = {}
ConnectFlag = False

# 生成SSL环境
context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
'''
PROTOCOL_TLS_CLIENT:
Auto-negotiate the highest protocol version like PROTOCOL_TLS, 
but only support client-side SSLSocket connections. 
The protocol enables CERT_REQUIRED and check_hostname by default.
'''
# 设置需要验证证书
#c ontext.verify_mode = ssl.CERT_REQUIRED

# 设置需要检查主机名
# context.check_hostname = True

# 加载信任根证书
context.load_verify_locations('CA_cert.crt')

# 选择使用加密套件
# 参考 https://www.openssl.org/docs/manmaster/man1/ciphers.html
# 密码套件 密钥交换算法-批量加密算法-消息认真码算法-伪随机函数
context.set_ciphers('AES256-SHA')

# 显示可用的加密方法列表
pprint.pprint(context.get_ciphers())

with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
    tryConnect = context.wrap_socket(sock, server_hostname='DNC')

def showCert(ctx):
    '''
    功能：提供可视化检查证书功能
    参数：
        ctx：由ssl.warp_sock()返回的SSLScoket对象
    '''
    cert = ctx.getpeercert()
    pprint.pprint(cert)

def ConfigImport():
    cfgfile = open("MES.cfg")
    content = cfgfile.read().split('\n')
    cfgfile.close()
    for i in range(0,4) :
        config[content[i].split(' ')[0]] = content[i].split(' ')[2]


def Connect2Server():
    try :
        tryConnect.connect((config['target'],int(config['port'])))

        tryConnect.cipher() # 启用加密
        print("Connect to server %s (port %s) successfully" % (config['target'],config['port']))
        return True
    except :
        print("Unable reach server %s (port %s)" % (config['target'],config['port']))
        return False


def deploy(Command):
    if '"' in Command :
        Command = Command.split("\"")
        while '' in Command :
            Command.remove('')
        if len(Command) <= 2 :
            print("Improper argument number.")
            return
        if os.path.exists(Command[1]) :
            file = open(Command[1],"r")
            Content = file.read()
        else :
            print("No such file to deploy.")
            return
        device = Command[2].split(' ')
        while '' in device:
            device.remove('')
    else :
        Command = Command.split(' ')
        while '' in Command :
            Command.remove('')
        if len(Command) <= 2 :
            print("Improper argument number.")
            return
        if os.path.exists(Command[1]) :
            file = open(Command[1],"r")
            Content = file.read()
        else :
            print("No such file to deploy.")
            return
        device = Command[2:]
    if 'A' in device :
        device = "A"
    else :
        flag = True
        for dev in device :
            try :
                num = int(dev)
            except :
                flag=False
                break
        if flag == False :
            print("Illegal argument(s) in deploy command.")
            return
        else :
            device='|||'.join(device)
    if len(Content) >= 102400 :
        print("Deploy file too big.")
        return
    sendmsg = "deploy " + device + "~~~" + Content
    try:
        tryConnect.sendall(sendmsg.encode('utf-8'))
    except:
        print("You are now disconnected from server")
        return



def status(Command):
    while '' in Command :
        Command.remove('')
        Command
    if len(Command) == 1:
        print("Improper argument number.")
        return
    flag = True
    if 'A' in Command :
        sendmsg = "status A"
        try:
            tryConnect.sendall(sendmsg.encode('utf-8'))
        except:
            print("You are now disconnected from server")
            return
    else :
        for i in range(1,len(Command)) :
            try :
                num = int(Command[i])
            except :
                flag = False
                break
        if flag == False :
            print("Illegal argument(s) in status command.")
            return
        sendmsg = ""
        for item in Command :
            sendmsg = sendmsg + item  + " "
        try :
            tryConnect.sendall(sendmsg[0:-1].encode('utf-8'))
        except :
            print("You are now disconnected from server")
            return

def FunctionCycle():
    # 显示证书
    showCert(tryConnect)
    function = ["status", "deploy", "help", "exit"]
    help = {"status":"Show status for NC device.\nUsage: status [device1] [device2] ... [A] [/?]",
            "deploy":"Deploy acsii commmand to NC device.\nUsage: deploy [acsii_file_path] [device1] [device2] ... [A] [/?]",
            "help"  :'Available command :"status", "deploy", "help", "exit";\nType "COMMAND /?" for details.'
            }
    print("MES contorl center")
    while True :
        print()
        Command = input("Command(type 'help' for help)\\")
        if ' ' in Command :
            Command = Command.split(' ')
            if Command[0] not in function :
                print("Command \"%s\" not found, please try again." % Command[0])
                continue
            if Command[0] == "help" or Command[0] == "exit" :
                print("Command \"%s\" has no argument(s), please try again." % Command[0])
                continue
            if Command[1] == "/?" :
                print(help[Command[0]])
                continue
            if Command[0] == "deploy" :
                deploy(' '.join(Command))
            elif Command[0] == "status" :
                status(Command)
        else :
            if Command not in function :
                print("Command \"%s\" not found, please try again." % Command)
                continue
            if Command == "exit" :
                tryConnect.sendall("finish".encode('utf-8'))
                break
            elif Command == "help" :
                print(help["help"])
                continue
            else :
                print("Command \"%s\" should have argument(s), please try again." % Command)





if __name__ == '__main__':
    ConfigImport()
    if Connect2Server() == True :
        FunctionCycle()
    else :
        print("Program shutting down...")
        time.sleep(1.5)