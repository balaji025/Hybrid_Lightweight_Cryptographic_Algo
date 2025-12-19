import os
from flask import Flask, render_template, request
from hybrid import demo_encrypt_ascon, demo_decrypt_ascon

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(__name__, template_folder=BASE_DIR)

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if request.method == 'POST':
        message = request.form['message']

        ciphertext, key, nonce = demo_encrypt_ascon(message)

        return render_template(
            "encrypt.html",
            encrypted_message=ciphertext.hex(),
            key=key.hex(),
            nonce=nonce.hex()
        )

    return render_template("encrypt.html")

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        ciphertext = bytes.fromhex(request.form['ciphertext'])
        key = bytes.fromhex(request.form['key'])
        nonce = bytes.fromhex(request.form['nonce'])

        decrypted_message = demo_decrypt_ascon(ciphertext, key, nonce)

        return render_template(
            "decrypt.html",
            decrypted_message=(
                decrypted_message.decode("utf-8", errors="ignore")
                if decrypted_message else "Decryption Failed!"
            )
        )

    return render_template("decrypt.html")


@app.route('/')
def home():
    return render_template("index.html")


# Local run only (PythonAnywhere uses WSGI, so this block won't run there)
if __name__ == '__main__':
    app.run(debug=True)
