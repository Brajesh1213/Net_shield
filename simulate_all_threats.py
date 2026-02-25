import os
import time
import socket
import threading
import sys
import subprocess

# --- Configuration ---
TEMP_DIR = os.environ.get('TEMP', 'C:\\Temp')
DOWNLOADS_DIR = os.path.join(os.path.expanduser('~'), 'Downloads')
MALICIOUS_IP = "127.0.0.1" # Using localhost for safety
MALICIOUS_PORT = 4444

def print_header(text):
    print("\n" + "="*60)
    print(f" [THREAT SIMULATION] {text}")
    print("="*60)

def simulate_steganography_image():
    print_header("Simulating Image Steganography (PE in PNG)")
    target = os.path.join(DOWNLOADS_DIR, "fake_image_threat.png")
    # Write "MZ" header (PE executable signature) into a PNG file
    try:
        with open(target, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)
        print(f"[+] Created: {target}")
        print("[!] NetSentinel should flag this as 'IMAGE STEGANOGRAPHY ALERT'")
    except Exception as e:
        print(f"[-] Error: {e}")

def simulate_steganography_pdf():
    print_header("Simulating Document Steganography (PE in PDF)")
    target = os.path.join(DOWNLOADS_DIR, "fake_doc_threat.pdf")
    # Write "MZ" header into a PDF file
    try:
        with open(target, "wb") as f:
            f.write(b"MZ" + b"\x00" * 100)
        print(f"[+] Created: {target}")
        print("[!] NetSentinel should flag this as 'DOCUMENT STEGANOGRAPHY ALERT'")
    except Exception as e:
        print(f"[-] Error: {e}")

def simulate_malware_drop():
    print_header("Simulating Malware Drop (.ps1 in Temp)")
    target = os.path.join(TEMP_DIR, "malicious_script.ps1")
    try:
        with open(target, "w") as f:
            f.write("Write-Host 'This is a simulation of a malicious script load'")
        print(f"[+] Created: {target}")
        print("[!] NetSentinel should flag this as 'MALWARE DROP: Executable/script appeared'")
    except Exception as e:
        print(f"[-] Error: {e}")

def simulate_rat_beaconing():
    print_header("Simulating RAT/C2 Beaconing (Network)")
    print("[*] Starting beaconing noise... (Connecting to 127.0.0.1:4444 every 2s)")
    
    # Start a dummy listener so the connection actually succeeds/attempts
    def start_dummy_listener():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(('127.0.0.1', MALICIOUS_PORT))
                s.listen()
                while True:
                    conn, addr = s.accept()
                    conn.close()
        except: pass

    threading.Thread(target=start_dummy_listener, daemon=True).start()

    def beacon():
        for i in range(5):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    s.connect(('127.0.0.1', MALICIOUS_PORT))
                    print(f"    [>] Beacon {i+1}/5 sent to 127.0.0.1")
            except:
                pass
            time.sleep(2)
    
    threading.Thread(target=beacon).start()
    print("[!] NetSentinel network monitor should see these connections.")

def simulate_masquerading():
    print_header("Simulating Process Masquerading")
    # We'll copy python.exe to a temp folder and rename it to svchost.exe
    target_dir = os.path.join(TEMP_DIR, "System32_Fake")
    if not os.path.exists(target_dir): os.makedirs(target_dir)
    
    fake_svchost = os.path.join(target_dir, "svchost.exe")
    python_exe = sys.executable
    
    try:
        import shutil
        shutil.copy(python_exe, fake_svchost)
        print(f"[+] Created fake system process: {fake_svchost}")
        print("[*] Launching fake svchost...")
        # Start the fake svchost (it will just exit immediately since it's just a copy of python)
        subprocess.Popen([fake_svchost, "-c", "import time; time.sleep(5)"])
        print("[!] NetSentinel should flag this as a MASQUERADING threat (system name in wrong path)")
    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    print("      NETSENTINEL THREAT SIMULATOR")
    print("      Run this while NetSentinel.exe is active.")
    
    simulate_steganography_image()
    time.sleep(1)
    simulate_steganography_pdf()
    time.sleep(1)
    simulate_malware_drop()
    time.sleep(1)
    simulate_masquerading()
    time.sleep(1)
    simulate_rat_beaconing()
    
    print("\n" + "="*60)
    print(" [DONE] All simulations launched.")
    print(" Check your NetSentinel console/logs for alerts!")
    print("="*60)
