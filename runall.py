import subprocess
import os

script1 = os.path.join("ActuallyVPN", "srv3.py")
script2 = os.path.join("ActuallyVPN", "clnt3.py")

process1 = subprocess.Popen(["start", "cmd", "/k", f"python {script1}"], shell=True)
process2 = subprocess.Popen(["start", "cmd", "/k", f"python {script2}"], shell=True)

process1.wait() #wait for script
process2.wait()


