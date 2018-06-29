#!/usr/bin/python
import os
import subprocess
for root, dirs, files in os.walk("/", topdown=False):
    for name in dirs:
    	subprocess.call(["./avu", root])



