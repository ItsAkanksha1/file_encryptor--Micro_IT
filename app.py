from flask import Flask, render_template, request, send_file, redirect, url_for, flash
from cryptography.fernet import Fernet
import os
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # for flash messages

UPLOAD_FOLDER = 'uploads'
PROCESSED_FOLDER = 'processed'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(PROCESSED_FOLDER, exist_ok=True)

# Helper: Convert password to valid Fernet key (using SHA256 + base64)
import base64
def generate_key_from_password(password):
    hash = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(hash)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    uploaded_file = request.files['file']
    password = request.form['password']

    if not uploaded_file or not password:
        flash("Missing file or password.")
        return redirect(url_for('index'))

    user_key = generate_key_from_password(password)
    cipher = Fernet(user_key)

    filename = uploaded_file.filename
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    encrypted_path = os.path.join(PROCESSED_FOLDER, f'encrypted_{filename}')

    uploaded_file.save(file_path)

    with open(file_path, 'rb') as f:
        data = f.read()

    encrypted_data = cipher.encrypt(data)

    with open(encrypted_path, 'wb') as f:
        f.write(encrypted_data)

    os.remove(file_path)

    return send_file(encrypted_path, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    uploaded_file = request.files['file']
    password = request.form['password']

    if not uploaded_file or not password:
        flash("Missing file or password.")
        return redirect(url_for('index'))

    user_key = generate_key_from_password(password)
    cipher = Fernet(user_key)

    filename = uploaded_file.filename
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    decrypted_path = os.path.join(PROCESSED_FOLDER, f'decrypted_{filename}')

    uploaded_file.save(file_path)

    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher.decrypt(encrypted_data)

        with open(decrypted_path, 'wb') as f:
            f.write(decrypted_data)

        os.remove(file_path)

        return send_file(decrypted_path, as_attachment=True)

    except Exception as e:
        os.remove(file_path)
        flash("Decryption failed: Wrong password or file is not encrypted.")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
