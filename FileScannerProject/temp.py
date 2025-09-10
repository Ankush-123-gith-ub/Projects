from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/scan', methods=['POST'])
def scan_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    # For testing, we just return the filename and size
    content = file.read()
    result = {
        "filename": file.filename,
        "size_bytes": len(content),
        "status": "file received"
    }
    return jsonify(result), 200

if __name__ == '__main__':
    app.run(host='localhost', port=5000)
