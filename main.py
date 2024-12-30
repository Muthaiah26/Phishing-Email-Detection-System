from flask import Flask, render_template, request, redirect, url_for, flash
import imaplib
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
import email
from email.header import decode_header
import re

app = Flask(__name__)
app.secret_key = 'muthu@2006'

PHISHING_KEYWORDS = ['urgent', 'verify your account', 'click here', 'login immediately', 'password', 'reset', 'secure']

MONGO_URI = "mongodb://localhost:27017/phishing"
try:
   client = MongoClient(MONGO_URI)
   db = client["Phishing"]  
   users_collection = db['Credentials']
   print("MongoDB connection successful!")
except Exception as e:
    print(f"Error connecting to MongoDB: {e}")

def connect_to_email(email_id, password, server="imap.gmail.com"):
    try:
        mail = imaplib.IMAP4_SSL(server)
        mail.login(email_id, password)
        return mail
    except Exception as e:
        return str(e)

def fetch_emails(mail, folder="inbox", num_emails=10):
    mail.select(folder)
    status, messages = mail.search(None, "ALL")
    email_ids = messages[0].split()[-num_emails:]  
    fetched_emails = []

    for email_id in email_ids:
        status, data = mail.fetch(email_id, "(RFC822)")
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                subject, encoding = decode_header(msg["Subject"])[0]
                if isinstance(subject, bytes):
                    subject = subject.decode(encoding if encoding else "utf-8")
                if msg.is_multipart():
                    for part in msg.walk():
                        content_type = part.get_content_type()
                        if content_type == "text/plain":
                            body = part.get_payload(decode=True).decode()
                            fetched_emails.append({"subject": subject, "body": body})
                            break
                else:
                    body = msg.get_payload(decode=True).decode()
                    fetched_emails.append({"subject": subject, "body": body})
    return fetched_emails

def analyze_email(email_body):
    urls = re.findall(r'https?://\S+', email_body)
    suspicious_urls = [url for url in urls if "bit.ly" in url or "tinyurl.com" in url]
    keyword_flags = [keyword for keyword in PHISHING_KEYWORDS if keyword in email_body.lower()]
    return {
        "total_urls": len(urls),
        "suspicious_urls": suspicious_urls,
        "phishing_keywords_detected": keyword_flags,
        "phishing_score": calculate_phishing_score(len(suspicious_urls), len(keyword_flags))
    }
def calculate_phishing_score(suspicious_url_count, keyword_count):
    score = suspicious_url_count * 2 + keyword_count
    if score > 5:
        return "High"
    elif score > 2:
        return "Medium"
    else:
        return "Low"


@app.route("/services", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        email_id = request.form.get("email")
        password = request.form.get("password")
        mail = connect_to_email(email_id, password)

        if isinstance(mail, str): 
            return render_template("index.html", error=mail)

        emails = fetch_emails(mail)
        results = []
        for email_content in emails:
            analysis = analyze_email(email_content["body"])
            results.append({
                "subject": email_content["subject"],
                "analysis": analysis
            })
        mail.logout()
        return render_template("results.html", results=results)

    return render_template("index.html")
@app.route("/contact")
def contact():
    return render_template("contact.html")
@app.route("/")
def home():
    return render_template("home.html")
@app.route("/services")
def services():
    return render_template("index.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name")
        email = request.form.get("email")
        password = request.form.get("password")

        if users_collection.find_one({"email": email}):
            flash("Email already registered. Please login.", "error")
            return redirect(url_for("login"))

        hashed_password = generate_password_hash(password, method="pbkdf2:sha256")
        users_collection.insert_one({
            "name": name,
            "email": email,
            "password": hashed_password
        })

        flash("Signup successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("signup.html")
@app.route("/login",methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = users_collection.find_one({"email": email})
        if not user:
            flash("Email not found. Please sign up.", "error")
            return redirect(url_for("signup"))

        if check_password_hash(user["password"], password):
            flash("Incorrect password. Please try again.", "error")
            return redirect(url_for("login"))

        return redirect(url_for("home"))
    return render_template("login.html")

if __name__ == "__main__":
    app.run(debug=True)
