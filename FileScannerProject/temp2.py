import requests

url = "http://localhost:5000/scan"
files = {'file': open(r'C:\Users\Asus\OneDrive\Documents\cyber-sb\Projects\FileScannerProject\test_files\harmless.txt', 'rb')}

response = requests.post(url, files=files)
print(response.status_code)
print(response.json())
