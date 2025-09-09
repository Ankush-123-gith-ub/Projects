import psutil

print("=== PROCESS LIST ===")
for proc in psutil.process_iter(['pid', 'name', 'exe']):
    print(proc.info)
