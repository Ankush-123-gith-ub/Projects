import os
import datetime
import psutil
import socket
import time
from collections import Counter
from check_filetype_hash_ext import check_extension_mismatch
from check_filetype_hash_ext import malware_hashes_check
from check_filetype_hash_ext import file_type_identifier
from check_filetype_hash_ext import check_file_signature

#-------------------------------------------  monitoring suspicious process by keywords and addr ----------------------------------


suspicious_keywords = ["keylogger", "kl", "hooker", "payload"]
whitelist = ["code.exe", "zoom.exe", "python.exe","zwebview2agent.exe","grammarly.desktop.exe","githubdesktop.exe"]
 
TRUSTED_SIGNATURES = {
    "code.exe": "Microsoft Corporation",
    "zoom.exe": "Zoom Video Communications, Inc.",
    "python.exe": "Python Software Foundation",
    "githubdesktop.exe": "GitHub, Inc.",
    "whatsapp.exe": "WhatsApp LLC",
    "chrome.exe": "Google LLC",
    "brave.exe": "Brave Software, Inc.",
    "spotify.exe": "Spotify AB",
    "steam.exe": "Valve Corporation"
}


suspicious_dirs = ["C:\\Users\\Asus\\AppData", "C:\\Users\\Asus\\Temp"]

suspicious_process = []
for proc in psutil.process_iter(['pid','name','exe']):
        try:
            if proc.info['name'] is None:
                name = ""
            else:
                name = proc.info['name'].lower()

            if proc.info['exe'] is None:
                 exe = ""
            else:
                 exe = proc.info['exe'].lower()
                
            keyword_suspicious = False
            for sus_key in suspicious_keywords:
                 if sus_key in name:
                      keyword_suspicious = True
                      break
                 
            keyword_path = False
            for sus_path in suspicious_dirs:
                 if exe.startswith(sus_path.lower()):
                      keyword_path = True
                      break
                 
            sig_suspicious = False
            if name in TRUSTED_SIGNATURES and exe:
                sig_status = check_file_signature(exe)
                if sig_status != "Valid":
                    sig_suspicious = True
                 
            if (keyword_suspicious or keyword_path or sig_suspicious) and name not in whitelist:
                suspicious_process.append({
                    "pid": proc.info['pid'],
                    "name": name,
                    "exe": exe,
                     "reason": f"Keyword={keyword_suspicious}, Path={keyword_path}, SignatureSuspicious={sig_suspicious}"
                })
        except psutil.NoSuchProcess:
        # Skip processes that no longer exist
            continue
        except psutil.AccessDenied:
        # Skip processes we don’t have permission to access
            continue

#---------------------------------------------------- Network Monitoring ----------------------------------------------------

SAFE_NAMES = {"code.exe", "zoom.exe", "brave.exe", "chrome.exe", "python.exe", "java.exe","postgres.exe", "steam.exe", "spotify.exe","whatsapp.exe","githubdesktop.exe"}
SAFE_REMOTE_PORTS = {80, 443}  # HTTP/HTTPS
KEY_STATES = {"ESTABLISHED", "SYN_SENT"}  # connection states to monitor
DURATION_SEC = 15
INTERVAL_SEC = 1

# --- Counter for repeated connections ---
counts = Counter()

for i in range(DURATION_SEC):
    for c in psutil.net_connections(kind="inet"):
        if not c.raddr or c.status not in KEY_STATES:
            continue
        try:
            if c.pid:
                 name = psutil.Process(c.pid).name().lower()
            else:
                 name = "unknown"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            name = "unknown"
        if c.raddr.ip.startswith("127.")  or c.raddr.port in SAFE_REMOTE_PORTS:
             continue
        
        exe_path = None
        try:
            if c.pid:
                exe_path = psutil.Process(c.pid).exe()
        except Exception:
                exe_path = None

        sig_suspicious = False
        if name in TRUSTED_SIGNATURES and exe_path:
            sig_status = check_file_signature(exe_path)
            if sig_status != "Valid":
                sig_suspicious = True
            else:
                continue  # signature valid → safe
        
        if c.laddr:
            laddr =  f"{c.laddr.ip}:{c.laddr.port}"
        else:
             laddr = ""
        raddr_ip = c.raddr.ip
        raddr_port = c.raddr.port

        try:
            rhost = socket.gethostbyaddr(raddr_ip)[0]
        except socket.herror:
            rhost = "UnknownHost"

        raddr = f"{raddr_ip}:{raddr_port} ({rhost})"

        key = (name,raddr)

        counts[key] +=1
    
    time.sleep(INTERVAL_SEC)



#---------------------------------------------------- main ---------------------------------------------------- 
total_files = 0
safe_count = 0
infected_count = 0
file_type_count = {}  # {"jpg": 2, "pdf": 3}
infected_files = []  # [("file.pdf", hash)]
mismatches = []  

folder  = r"test_files"
folder1= r"C:\Users\Asus\Downloads"
for root, dirs, files in os.walk(folder):
    for file in files:
        total_files += 1
        file_path = os.path.join(root, file)
        print(f"Scanning: {file_path}")
        if os.path.isfile(file_path):
            
            try:
                mismatch, ext, detected = check_extension_mismatch(file_path)
                if mismatch:
                    mismatches.append((file, ext, detected))
            except Exception as e:
                print(f"Skipping file {file_path}, error: {e}")


            ##### count safe and infected files and stroing with name ####
            is_malware,name,h = malware_hashes_check(file_path)
            if not is_malware:
                safe_count += 1
            else:
                
                #   infected_files[infected_count] = (file,malware_hashes_check(file_path)) wrong 
                infected_count+=1
                infected_files.append((file,name,h))
            
            ###### file type count#######
            detected = file_type_identifier(file_path)
            if detected in file_type_count:
                file_type_count[detected] += 1
            else:
                file_type_count[detected] = 1


#---------------------------------------------------- writing file ----------------------------------------------------
time_stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
scanner_file_path = fr"Reports\Scanner_report_{time_stamp}.txt"
THRESHOLD = max(5, DURATION_SEC // 2)
os.makedirs(os.path.dirname(scanner_file_path), exist_ok=True)
with open(scanner_file_path,"w") as report:
    report.write(f"Total files scanned: {total_files}\n")
    report.write(f"Safe files: {safe_count}\n")
    report.write(f"Infected files: {infected_count}\n")
    report.write("\n")

    report.write("File types detected:\n")
    report.write("\n" + "-"*60 + "\n")
    for file,count in file_type_count.items():
        report.write(f"    {file}: {count}\n")
    report.write("\n")


    report.write("\n" + "-"*60 + "\n")

    report.write("Infected files:\n")
    if infected_count:
        for file,name,h in infected_files:
            report.write(f"    {file} --> Infected({h}) with ({name})\n")



    report.write("\n" + "-"*60 + "\n")
    report.write("\nMismatched file extensions:\n")
    if mismatches:
            for file, ext, detected in mismatches:
                report.write(f"    [WARNING] {file}: [extension .{ext}] does not match detected type {detected}\n")
    else:
        report.write("    None detected\n")

    
    report.write("\n" + "-"*60 + "\n")
    report.write("Suspicious Processes:\n")
    if suspicious_process:
         for proc in suspicious_process:
            report.write(f"     PID: {proc['pid']}, Name: {proc['name']}, Path: {proc['exe']}, Reason: {proc['reason']}\n")
    else:
          report.write("    None detected\n")

    report.write("\n" + "-"*60 + "\n")
    report.write("\nRepeated suspicious connections:\n")
    if counts:
        report.write("\nTop 10 repeated suspicious connections:\n")
        for (name, raddr), n in counts.most_common(10):
            report.write(f"{n:>3} times -> Process: {name:<20} Remote: {raddr}\n")
        
        report.write("\nConnections above threshold:\n")
        for (name, raddr), n in counts.most_common(10):
             if n > THRESHOLD:
                report.write(f"[ALERT] {n:>3} times -> Process: {name:<20} Remote: {raddr}\n")

    else:
        report.write("None detected\n")     
print("Report Done Succesfully.")    
# Console summary
print("===== Scan Summary =====")
print(f"Total files scanned: {total_files}")
print(f"Safe files: {safe_count}")
print(f"Infected files: {infected_count}")
print(f"Report saved at: {scanner_file_path}")
print(f"Suspicius process: {suspicious_process}")
print(f"\nTop repeated suspicious connections (over {DURATION_SEC} sec):\n")
for (name, raddr), n in counts.most_common(10):
     print(f"{n:>3} times -> Process: {name:<20} Remote: {raddr}")
print(f"\nTotal unique suspicious connections: {len(counts)}")     

#------------------------------------------------------------------------------------------------------------------------------------------
