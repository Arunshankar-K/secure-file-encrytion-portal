from flask import (
    Flask,
    request,
    render_template,
    send_file,
    redirect,
    url_for,
    session,
    after_this_request
)

from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from crypto_utils import generate_key, encrypt_file, decrypt_file
from key_manager import protect_key, unprotect_key
from database import (
    init_db,
    create_user,
    authenticate_user,
    get_connection
)
from dotenv import load_dotenv
from cryptography.exceptions import InvalidTag

import os
import uuid
import tempfile
import logging

load_dotenv()

logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)

security_logger = logging.getLogger("security")

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

app.secret_key = os.environ["FLASK_SECRET_KEY"]

csrf = CSRFProtect(app)

UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"
KEY_FOLDER = "keys"

for folder in [
    UPLOAD_FOLDER,
    ENCRYPTED_FOLDER,
    DECRYPTED_FOLDER,
    KEY_FOLDER
]:
    os.makedirs(folder, exist_ok=True)

init_db()


@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))

    return render_template(
        "index.html",
        username=session["username"]
    )


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            return "Username and password are required", 400

        if len(password) < 8:
            return "Password must contain at least 8 characters", 400

        if create_user(username, password):
            return redirect(url_for("login"))

        return "Username already exists", 400

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = authenticate_user(username, password)

        if user:

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            security_logger.info(
                "LOGIN_SUCCESS user_id=%s",
                user["id"]
            )
            return redirect(url_for("index"))

        security_logger.warning(
            "LOGIN_FAILED username=%s",
            username
        )
        return "Invalid username or password", 401

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))


@app.route("/encrypt", methods=["POST"])
def encrypt():

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = request.files.get("file")

    if not file or file.filename == "":
        return "No file selected", 400

    original_filename = secure_filename(file.filename)

    if not original_filename:
        return "Invalid filename", 400

    file_id = str(uuid.uuid4())

    input_path = os.path.join(
        UPLOAD_FOLDER,
        file_id
    )

    encrypted_path = os.path.join(
        ENCRYPTED_FOLDER,
        file_id + ".enc"
    )

    key_path = os.path.join(
        KEY_FOLDER,
        file_id + ".key"
    )

    file.save(input_path)

    try:
        aes_key = generate_key()

        encrypt_file(
            input_path,
            encrypted_path,
            aes_key
        )

        protected_key = protect_key(aes_key)

        with open(key_path, "wb") as key_file:
            key_file.write(protected_key)

        security_logger.info(
            "FILE_ENCRYPTED user_id=%s file_id=%s",
            session["user_id"],
            file_id
        )

    finally:
        if os.path.exists(input_path):
            os.remove(input_path)

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO files
        (
            file_id,
            user_id,
            original_filename,
            encrypted_filename
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            file_id,
            session["user_id"],
            original_filename,
            file_id + ".enc"
        )
    )

    connection.commit()
    connection.close()

    return send_file(
        encrypted_path,
        as_attachment=True,
        download_name=file_id + ".enc"
    )


@app.route("/decrypt", methods=["POST"])
def decrypt():

    if "user_id" not in session:
        return redirect(url_for("login"))

    file = request.files.get("file")

    if not file or file.filename == "":
        return "No file selected", 400

    if not file.filename.endswith(".enc"):
        return "Please upload an encrypted .enc file", 400

    encrypted_filename = secure_filename(file.filename)
    file_id = encrypted_filename[:-4]

    connection = get_connection()

    record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE file_id = ?
        AND user_id = ?
        """,
        (
            file_id,
            session["user_id"]
        )
    ).fetchone()

    connection.close()

    if record is None:
        security_logger.warning(
            "ACCESS_DENIED user_id=%s file_id=%s",
            session["user_id"],
            file_id
        )

        return "File not found or access denied", 403

    key_path = os.path.join(
        KEY_FOLDER,
        file_id + ".key"
    )

    if not os.path.exists(key_path):
        security_logger.warning(
            "KEY_NOT_FOUND user_id=%s file_id=%s",
            session["user_id"],
            file_id
        )

        return "Encryption key not found", 404

    decrypted_path = os.path.join(
        DECRYPTED_FOLDER,
        file_id + "_decrypted"
    )

    # Create a temporary location for the uploaded encrypted file.
    temp_dir = tempfile.mkdtemp()
    temp_encrypted_path = os.path.join(
        temp_dir,
        encrypted_filename
    )

    try:
        # Save the uploaded ciphertext only to the temporary directory.
        file.save(temp_encrypted_path)

        with open(key_path, "rb") as key_file:
            protected_key = key_file.read()

        aes_key = unprotect_key(protected_key)

        decrypt_file(
            temp_encrypted_path,
            decrypted_path,
            aes_key
        )

        security_logger.info(
            "FILE_DECRYPTED user_id=%s file_id=%s",
            session["user_id"],
            file_id
        )

    except InvalidTag:
        security_logger.warning(
            "DECRYPTION_FAILED user_id=%s file_id=%s",
            session.get("user_id"),
            file_id
        )

        return (
            "Decryption failed. "
            "The file may have been modified or the key is invalid."
        ), 400

    finally:
        # Always remove the temporary uploaded ciphertext.
        try:
            if os.path.exists(temp_encrypted_path):
                os.remove(temp_encrypted_path)

            os.rmdir(temp_dir)

        except OSError:
            pass

    @after_this_request
    def cleanup_decrypted_file(response):
        try:
            if os.path.exists(decrypted_path):
                os.remove(decrypted_path)
        except OSError:
            pass

        return response

    return send_file(
        decrypted_path,
        as_attachment=True,
        download_name=record["original_filename"]
    )

@app.errorhandler(413)
def request_entity_too_large(error):
    security_logger.warning(
        "UPLOAD_TOO_LARGE ip=%s",
        request.remote_addr
    )
    return (
        "<h1>Upload rejected</h1>"
        "<p>The maximum allowed file size is 10 MB.</p>"
        "<p>Please choose a smaller file.</p>"
    ), 413

if __name__ == "__main__":
    app.run(debug=False)
