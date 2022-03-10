import os
import platform
from socket import *
import ipaddress

from sqlalchemy import null

class Scanner:

    def __init__ (self):
        self.well_known={
            20:"FTP",
            21:"FTP",
            23:"TELNET",
            53:"DNS",
            67:"DHCP",
            68:"DHCP",
            80:"HTTP",
            22:"SSH",
            118:"SQL",
            123:"NTP",
            135:"NetBIOS",
            136:"NetBIOS",
            137:"NetBIOS",
            138:"NetBIOS",
            139:"NetBIOS",
            156:"SQL",
            443:"HTTPS",
            514:"Shell",
            750:"KerberosIV",
            3306:"MySQL",
            5432:"Postgres",
            5433:"Postgres"
        }

    def create_ips(self, ip, cidr):

        hostList = []

        network = ipaddress.ip_network(ip+"/"+cidr)

        for i in network.hosts():
            hostList.append(str(i))

        return hostList
    
    def host_scan(self, ip, start, end):
        print("\nhost: "+ip+"\n")
        for i in range(start, end):
            s = socket(AF_INET, SOCK_STREAM)
            conn = s.connect_ex((ip, i))
            if(conn == 0) :
                if(i in self.well_known.keys()):
                    print (f'{self.well_known[i]} {i} : OPEN')
                else:
                    print (f'Port {i}: OPEN')
            s.close()
    
    def network_scan(self, ip, cidr, start, end):
        hostList = self.create_ips(ip, cidr)
        for host in hostList:
            self.host_scan(host, start, end)
    
def Main():
    scanner = Scanner()
    setdefaulttimeout(0.01)
    while(True):
        entrada=input("\n1-host port scan\n2-network port scan\n0-quit\n")
        if (entrada=="1"):
            valid=True
            ip=input("digite o ip (-1 para cancelar): ")
            if(ip == "-1"):
                valid=False
            try:
                inet_aton(ip)
            except:
                print("IP invalido")
                valid=False
            if(valid):
                print("digite o intervalod das portas\n")
                start=int(input("comeco: "))
                end=int(input("fim: "))
                if(start>end):
                    valid=False
                if(start<0 or end>65535):
                    valid=False
            if(valid):
                scanner.host_scan(ip,start,end)
        elif (entrada=="2"):
            valid=True
            ip=input("digite o ip (-1 para cancelar): ")
            if(ip == "-1"):
                valid=False
            try:
                inet_aton(ip)
            except:
                print("IP invalido")
                valid=False
            if(valid):
                cidr=input("digite o cidr (-1 para cancelar): ")
                if(cidr == "-1"):
                    valid=False
                if(not(32>int(cidr)>=0)):
                    valid=False
            if(valid):
                print("digite o intervalod das portas\n")
                start=int(input("comeco: "))
                end=int(input("fim: "))
                if(start>end):
                    valid=False
                if(start<0 or end>65535):
                    valid=False
            scanner.network_scan(ip,cidr,start,end)
        elif (entrada == "0"):
            break
        else:
            print("Entrada invalida")

if __name__ == "__main__":
    Main()