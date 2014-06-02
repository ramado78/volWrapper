#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Volatility Wrapper by S2 Grupo

Desc: Wrapper for volatility memory analizer tool
Version: 0.1
Author: Roberto Amado ramado@s2grupo.es
Date: August 2013 
"""

import fileinput
import argparse
import sys


class VolatilityWrapper():
    """VolatilityWrapper

    Clase base encargada de realizar el parsing de entrada del usuario, así
    como capturar la salida estandar del volatility.
    """

    def __init__(self):
        self.W  = "\033[0m";  # white (normal)
        self.BLA= "\033[30m"; # black
        self.R  = "\033[31m"; # red
        self.G  = "\033[32m"; # green
        self.O  = "\033[33m"; # orange
        self.B  = "\033[34m"; # blue
        self.P  = "\033[35m"; # purple
        self.C  = "\033[36m"; # cyan
        self.GR = "\033[37m"; # gray
        
        self.args, self.parser =  self.parseOptions()
        for line in sys.stdin:
            self.analize(line)
            
        self.printLegend()
        
    def parseOptions(self):
        self.parser = argparse.ArgumentParser()
        self.parser.add_argument("-c", "--comments", help="Show dll info ",
                                 action="store_true")
    

        self.args = self.parser.parse_args()
        return self.args,self.parser 
    
    def analize(self, line):
        raise NotImplementedError()    
    
    def printLegend(self):    
        raise NotImplementedError()    
    
class SuspiciousDlls(VolatilityWrapper):
    """SuspiciousDlls 
    
    * Opción Volatility: dlllist
    * Opciónes volwrapper: -c para ver los comentarios sobre cada dll
    * Descripción: Clase que identifica que librerias .dll dentro de system32 
    son típicas en un sistema Windows mediante un código de colores. Solo 
    checkea el nombre contra el archivo dlls.txt, eso quiere decir que si un
    malware ha sobreescrito la dll este sistema no la detectará. Para eso 
    comprueba la firma asociada. 
    """    
    
    def __init__(self): 
        self.net_dlls = ['netman.dll','wtsapi32.dll','wshtcpip.dll'
                         ,'wshtcpip.dll', 'icmp.dll', 'ieframe.dll'
                         ,'mswsock.dll', 'netapi32.dll', 'url.dll'
                         ,'urlmon.dll', 'wininet.dll', 'wsock32.dll'
                         ,'ws2_32.dll', 'ws2help.dll']
        
        self.crypto_dlls = ['schannel.dll', 'secur32.dll', 'crypt32.dll'
                            ,'cryptdll.dll', 'cryptsvc.dll', 'cryptui.dll']
        VolatilityWrapper.__init__(self)
    
    def findDLL(self,name):

        fi = open('dlls.txt', 'r')
        for l in fi:
            name_in_file = l.split(' ')[0].lower()
            if (name == name_in_file):
                fi.close()
                return l[:-1]
        fi.close()
        return False

    def analize(self, line):
            aux = line
            aux = aux.lower()
            if ('.dll' in aux or '.drv' in aux) and 'system32' in aux:
                name = aux.split('\\system32\\')[1][:-1].lower()
                result = self.findDLL(name)
                if result:
                    
                    if name in self.net_dlls:
                        
                        if self.args.comments:
                            print self.O + line[:-1] + ' - ' + result + self.W
                        else:
                            print (self.O + line[:-1] + self.W)
                            
                    elif name in self.crypto_dlls:
                        if self.args.comments:
                            print self.R + line[:-1] + ' - ' + result + self.W
                        else:
                            print (self.R + line[:-1] + self.W)
                    else:
                        if self.args.comments:
                            print self.G + line[:-1] + ' - ' + result + self.W
                        else:
                            print (self.G + line[:-1] + self.W)
                        
                else:
                    print line[:-1]
            else:
                print line[:-1]
                
    def printLegend(self):
        print "\nLEGEND"
        print "--------"

        print self.G + "GREEN : Normal known DLLs in system32 directory"
        print self.O + "ORANGE : Normal known DLLs in system32 directory \
 with network functions"
        print self.R + "RED : Normal known DLLs in system32 directory \
 with cryptography functions"
        print self.W + "WHITE : Unknown DLLs or .exe files out of \
 system32"

class OrphanProcess(VolatilityWrapper):
    """OrphanProcess 
    
    * Opción Volatility: pslist
    * Opciónes volwrapper: N/A
    * Descripción: Clase que identifica si un proceso no tiene padre, este puede
    encontrarse oculto lo que ya es de por si una anómalia.
    """    
    
    def __init__(self): 
        self.pidlist = []
        self.ppidlist = []
        VolatilityWrapper.__init__(self)
        
    def analize(self, line):
        pid = line[32:38].replace(' ', '')
        ppid = line[39:45].replace(' ', '')
        if ppid not in self.pidlist and pid != '------':
            print self.R + line[:-1] + self.W
        else:
            print self.W + line[:-1]
            
        self.pidlist.append(pid)
                
    def printLegend(self):
        print "\nLEGEND"
        print "--------"

        print self.R + "RED : Orphan process without parent" + self.W

class OrphanProcess2(VolatilityWrapper):
    """OrphanProcess 
    
    * Opción Volatility: psscan
    * Opciónes volwrapper: N/A
    * Descripción: Clase que identifica si un proceso no tiene padre, este puede
    encontrarse oculto lo que ya es de por si una anómalia.
    """    
    
    def __init__(self): 
        self.pidlist = []
        self.ppidlist = []
        self.pidDicc = {}
        VolatilityWrapper.__init__(self)
        
    def analize(self, line):
        pid = line[27:34].replace(' ', '')
        if pid != '------':
            self.pidDicc[int(pid)] = line
            self.pidlist.append(int(pid))
        else:
            print line[:-1]
    def printLegend(self):       
        for pid in sorted(self.pidDicc.iterkeys()):
            ppid = int(self.pidDicc[pid][34:41].replace(' ', ''))
            if ppid not in self.pidlist:
                print self.R + self.pidDicc[pid][:-1] + self.W
            else:
                print self.W + self.pidDicc[pid][:-1]
        
        print "\nLEGEND"
        print "--------"

        print self.R + "RED : Orphan process without parent" + self.W

def main():
    """main
    
    Ese cuerpo!
    """  
    line = sys.stdin.readline()

    if '************************************************************************' in line:
        print "Dllss  Wrapper"
        print line[:-1]
        SuspiciousDlls()
        
    if 'Offset(V)' in line and 'Thds' in line and 'Hnds' in line and 'Wow64' in line:
        print "OrphanProcess Wrapper pslist"
        print line[:-1]
        OrphanProcess()

    if 'Offset(P)' in line and 'PDB' in line and 'Time' in line:    
        print "OrphanProcess Wrapper psscan"
        print line[:-1]
        OrphanProcess2()        

    else:
        print "No wrapper used"
        print line[:-1]
        for line in sys.stdin:
            print line[:-1]
        
if __name__ == "__main__":
    sys.exit(main())











