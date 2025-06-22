from flask import Flask, render_template, request, send_file
from stego_module import hide_message, extract_message
import os
import uuid

from flask_cors import CORS 

app = Flask(__name__)

CORS(app)

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

ENCRYPTED_FOLDER = 'static/encrypted'
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        mode = request.form.get("mode")
        key = request.form.get("key")


        ####### Encryption #######
        if mode == "encrypt":
            message = request.form.get("message")
            image_file = request.files.get("image")
            
            if not message or not key or not image_file:
                return render_template("index.html", error="All fields are required for encryption.")

            # Save original image
            input_path = os.path.join(app.config['UPLOAD_FOLDER'], str(uuid.uuid4()) + "_" + image_file.filename) # type: ignore
            image_file.save(input_path)

            output_path = input_path.replace(".", "_encoded.")

            try:
                hide_message(input_path, output_path, message, key)
                return render_template("index.html", output_image=output_path)
            except Exception as e:
                return render_template("index.html", error=str(e))


        ####### Decryption #######
        elif mode == "decrypt":
            image_file = request.files.get("image")

            if not key or not image_file:
                return render_template("index.html", error="Image and key required for decryption.")

            # Save image
            input_path = os.path.join(app.config['ENCRYPTED_FOLDER'], str(uuid.uuid4()) + "_" + image_file.filename) # type: ignore ## here just the file name is made unique with uuid
            image_file.save(input_path)

            try:
                hidden_msg = extract_message(input_path, key)
                return render_template("index.html", decrypted_message=hidden_msg)
            except Exception as e:
                return render_template("index.html", error=str(e))
    
    return render_template("index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
