import os 
import hashlib
import filetype
import pandas as pd

#---------------------------------------------------- file type check ----------------------------------------------------
def file_type_identifier(path):
    try:
        kind = filetype.guess(path)
        if kind is not None:
            return kind.extension
    except:
        pass

    magic_numbers = {
        b"MZ": "exe",          
        b"PK\x03\x04": "zip",  
        b"Rar!": "rar",
        b"\x7fELF": "elf",     
        b"%PDF": "pdf",
        b"\x89PNG": "png",
        b"\xff\xd8\xff": "jpg",
        b"GIF": "gif",
        b"II*\x00": "tif",    
        b"MM\x00*": "tif",    
        b"\x25\x21": "ps",    
        b"7z\xbc\xaf": "7z",  
        b"\x1f\x8b": "gz",    
        b"PK\x07\x08": "zip",
    }

    try:
        with open(path, "rb") as f:
            header = f.read(8) 
            for binary_n, ext in magic_numbers.items():
                if header.startswith(binary_n):
                    return ext
    except:
        pass

    return "Unknown"

#---------------------------------------------------- mismatch check ----------------------------------------------------
def check_extension_mismatch(path):
    ext = os.path.splitext(path)[1].lower().replace('.', '')  
    detected_type = file_type_identifier(path)

    text_like = {
    "txt", "md", "srt", "ini", "html", "xml", "json", "js", "ts", "yml", "yaml",
    "map", "aspx", "css", "py", "c", "cpp", "h", "java", "class", "kt", "pl", "cmd",
    "xsl", "bb", "mf", "properties", "smali", "rsa", "sf", "pom", "xm", "asc",
    "gyp", "jfc", "doi", "download", "sys", "inf", "bnf", "mjs", "less", "svg", "a",
    "ovpn","url","toml","kts","importorder","default","flex","dekstop","dex",
    "tmpl","jcst","raung","mocmaker","dsa","jadxplugin","bb2","dr-farfar","info",
    "prefs","mappings","e4xmi","graffle","log","4","10","11","instance","xmi",
    "setup","6","7","dictionary","jnlib","jsa","access","policy","src","ja",
    "certs","named","tmlanguage","sh","jsonc","cjs","jade","flow","cc","hh",
    "node","iml","nixl","gypi","mts","tsbuildinfo","gdnsuppress","cat"
}


    zip_based = {"zip", "jar", "apk", "docx", "pptx", "xlsx"}
    harmless_image = {"jpg", "jpeg", "png", "webp", "gif", "bmp", "tif", "tiff"}

    custom_mapping = {
        "msi": ["xls", "doc"],     
        "apkm": ["zip"],           
        "vbox-extpack": ["gz"],    
        "m3u8_in": ["Unknown"],    
        "jar": ["zip"],            
        "pptx": ["zip"],           
        "docx": ["zip"],           
        "xlsx": ["zip"],           
        "apk": ["zip"],   
         "aar": ["zip"],
        "dll": ["exe"],     # DLL/EXE share MZ header
        "so": ["elf"],      # Linux shared object
         "sym": ["zip"],
        "lib": ["ar"],
        "dat": ["zip"],         
    }

    safe_ignore = {
        "msi": {"Unknown"},     
        "iso": {"Unknown"},    
        "der": {"Unknown"},     
        "m3u8_in": {"Unknown"}, 
    }

    critical_exec = {"exe", "dll", "msi", "bat", "com", "scr"}

    # ---------------------- rules ----------------------
    if ext in custom_mapping and detected_type in custom_mapping[ext]:
        return False, ext, detected_type
    if ext in safe_ignore and detected_type in safe_ignore[ext]:
        return False, ext, detected_type
    if ext in text_like and detected_type == "Unknown":
        return False, ext, detected_type
    if ext in zip_based and detected_type == "zip":
        return False, ext, detected_type
    if ext in harmless_image and detected_type in harmless_image:
        return False, ext, detected_type

    if detected_type in critical_exec and ext not in critical_exec:
        return True, ext, detected_type
    if ext in critical_exec and detected_type == "Unknown":
        return True, ext, detected_type

    if ext and ext != detected_type:
        return True, ext, detected_type

    return False, ext, detected_type

#----------------------------------------------------  check malicious file  ----------------------------------------------------

csv_path = r"C:\Users\Asus\OneDrive\Documents\cyber-sb\full.csv"

df = pd.read_csv(csv_path, on_bad_lines='skip', skipinitialspace=True)

df.columns = df.columns.str.strip().str.replace('"','').str.replace('#','')

for col in ["md5_hash", "sha1_hash", "sha256_hash"]:
    if col in df.columns:
        df[col] = df[col].astype(str).str.strip().str.replace('"','')

md5_set = set(df["md5_hash"].dropna()) if "md5_hash" in df.columns else set()
sha1_set = set(df["sha1_hash"].dropna()) if "sha1_hash" in df.columns else set()
sha256_set = set(df["sha256_hash"].dropna()) if "sha256_hash" in df.columns else set()


# ----------------- Calculate Hashes of a File -----------------
def get_hash_file(path, chunk_size=4096):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(path, "rb") as f:
        while chunk := f.read(chunk_size):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

# ----------------- Check if File is Malware -----------------
def malware_hashes_check(path):
    file_hashes = get_hash_file(path)

    if file_hashes["md5"] in md5_set:
        return True, "MD5", file_hashes["md5"]
    elif file_hashes["sha1"] in sha1_set:
        return True, "SHA1", file_hashes["sha1"]
    elif file_hashes["sha256"] in sha256_set:
        return True, "SHA256", file_hashes["sha256"]

    return False, None, None