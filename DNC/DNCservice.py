import socket
from ssl import wrap_socket
import os
import ssl

config = {}

def configinport():
    cfgfile = open("DNC.cfg")
    content = cfgfile.read().split('\n')
    cfgfile.close()
    for i in range(0,4) :
        config[content[i].split(' ')[0]] = content[i].split(' ')[2]

def RequestStatus(Command,Client) :
    if "A" in Command :
        Device = ["A"]
    else :
        Device = Command[1:]
    print(Device)

def RequestDeploy(Command,Client) :
    Data = Command.split("~~~")
    Device = Data[0].split("|||")
    Content = Data[1]
    print(Device)
    print(Content)

def StartService():
    # 生成SSL环境
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # 加载服务器所用证书和私钥
    context.load_cert_chain('DNC_cert.crt', 'DNC_rsa_private.key')

    sk = socket.socket()
    sk.bind((config["host"],int(config["port"])))
    sk.listen(1)
    ssl_sk = context.wrap_socket(sk, server_side=True)
    while True :
        client, addr = ssl_sk.accept()
        while True :
            ret_bytes = client.recv(10240)
            Receive = str(ret_bytes,encoding="utf-8")
            if (Receive == "finish") :
                break
            if (Receive.split(" ")[0] == "status") :
                RequestStatus(Receive.split(" "),client)
            if (Receive.split(" ")[0] == "deploy") :
                RequestDeploy(Receive.split(" ")[1],client)
        client.close()
        print("finished")
    ssl_sk.close()

if __name__ == '__main__':
    configinport()
    StartService()



