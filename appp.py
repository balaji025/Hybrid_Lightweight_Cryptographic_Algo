from flask import Flask, request, render_template, jsonify
from encrypt2 import demo_hybrid_encrypt

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # Your HTML frontend file

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.form['user_input']  # Get user input from the frontend
    encrypted_data = demo_hybrid_encrypt(data)  # Encrypt the user input using your algorithm
    return jsonify({'encrypted': encrypted_data})  # Send the result back as JSON

if __name__ == "__main__":
    app.run(debug=True)
