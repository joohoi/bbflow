from runner import Runner
from domains import SubdomainScannerAmass
import time

x = SubdomainScannerAmass("io.fi")
x.start(recursive=True)
print("uoo")