from socket import gethostbyname
from sys import argv
from re import compile

domain_regex = compile(r"^[a-zA-Z0-9]+\.[a-z]{2,5}$")

if domain_regex.match(argv[1]):
  print("true")
else:
  print("false")




