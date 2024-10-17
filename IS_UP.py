from sys import argv
from ipaddress import IPv4Address
from os import system

try:
    
    IPv4Address(argv[1])
    
    result=system(f"ping {argv[1]} > null 2>&1")
    
    if result == 0 :
        print("UP !")
    else:
        print("DOWN !")

except :
    print("On dirait qu'il y a un soucis")



