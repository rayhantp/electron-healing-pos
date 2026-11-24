import sys
sys.path.insert(0, r"C:\Users\PC 1\.gemini\antigravity\scratch\electron-healing-pos\resources\engine")
from winbio_client import WinBioHardwareManager
import time

mgr = WinBioHardwareManager()
res_box = []
def on_res(r):
    res_box.append(r)

mgr.scan_fingerprint_async(on_res, timeout_seconds=2)
time.sleep(3)
print("Result:", res_box)

