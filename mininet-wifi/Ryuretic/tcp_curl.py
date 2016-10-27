import os
import time


for i in range(20):
    os.system('curl www.google.com')
    time.sleep(3)
    os.system('curl www.w3schools.org')
    time.sleep(3)

              

