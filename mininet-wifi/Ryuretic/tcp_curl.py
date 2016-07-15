import os
import time


for i in range(15):
    os.system('curl www.google.com')
    time.sleep(10)
    os.system('curl www.w3schools.org')
    time.sleep(10)

