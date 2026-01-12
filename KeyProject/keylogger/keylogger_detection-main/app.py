# from flask import Flask, render_template, request, redirect, url_for, session
# from detector import scanner

# app = Flask(__name__)
# app.secret_key = "super_secret_key_123"  # For session handling

# # Dummy login credentials
# USERS = {"admin": "admin123", "student": "project2025"}

# @app.route('/')
# def home():
#     return render_template('home.html')

# @app.route('/service')
# def service():
#     # Require login to access service page
#     if 'user' not in session:
#         return redirect(url_for('login'))
#     return render_template('service.html')

# # @app.route('/run_scan', methods=['POST'])
# # def run_scan():
# #     # Require login to run scan
# #     if 'user' not in session:
# #         return redirect(url_for('login'))

# #     results = {
# #         "folders": scanner.check_refog_folders(),
# #         "processes": scanner.check_suspicious_processes(),
# #     }
# #     return render_template('service.html', results=results)





# @app.route('/run_scan', methods=['POST'])
# def run_scan():
#     if 'user' not in session:
#         return redirect(url_for('login'))

#     scan_log = scanner.full_scan()  # returns a list of log lines
#     return render_template('service.html', scan_log=scan_log)





# @app.route('/login', methods=['GET', 'POST'])
# def login():
#     if request.method == 'POST':
#         username = request.form.get('username')
#         password = request.form.get('password')

#         if username in USERS and USERS[username] == password:
#             session['user'] = username
#             return redirect(url_for('service'))
#         else:
#             return render_template('login.html', error="Invalid credentials!")
#     return render_template('login.html')

# @app.route('/logout')
# def logout():
#     session.pop('user', None)
#     return redirect(url_for('home'))

# @app.route('/support')
# def support():
#     return render_template('support.html')

# @app.route('/feedback', methods=['GET', 'POST'])
# def feedback():
#     if request.method == 'POST':
#         feedback_text = request.form.get('feedback')
#         with open("feedback.txt", "a", encoding='utf-8') as f:
#             f.write(f"User Feedback: {feedback_text}\n")
#         return render_template('feedback.html', message="Thank you for your feedback!")
#     return render_template('feedback.html')

# if __name__ == '__main__':
#     app.run(debug=True)









from flask import Flask, render_template, request, redirect, url_for, session
from detector.scanner import run_full_scan
from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")

db = client['projectDB']  # Database name

users_col = db['users']              # For login credentials
feedback_col = db['feedbacks']       # For feedback messages
support_col = db['support_requests']

# Create Flask app
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Needed for session handling

# ------------------ ROUTES ------------------

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = users_col.insert_one({'username': username, 'password': password})
        if user:
            session['user'] = username  # ✅ Set session
            return redirect(url_for('service'))  # Go to service page
        else:
            return render_template('login.html', error="Invalid credentials!")

    return render_template('login.html')

@app.route('/service')
def service():
    # Check if user is logged in
    if 'user' not in session:
        return redirect(url_for('login'))

    # Run full system scan
    logs = run_full_scan()
    return render_template('service.html', logs=logs)

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('home'))



@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        # Handle feedback form submission
        name = request.form['name']
        email = request.form['email']
        message = request.form['message']

        # You can store it in a file or database
        feedback_col.insert_one({"name": name, "email": email, "message": message})


        return render_template('feedback.html', success=True)

    return render_template('feedback.html', success=False)



@app.route('/support', methods=['GET', 'POST'])
def support():
    if request.method == 'POST':
        # Get support form details
        name = request.form['name']
        email = request.form['email']
        issue = request.form['issue']

        # Save to a file for demo (or could send email in real app)
        support_col.insert_one({"name": name, "email": email, "issue": issue})


        return render_template('support.html', success=True)

    return render_template('support.html', success=False)


# ------------------ MAIN ------------------

if __name__ == "__main__":
    # Insert a test admin user if not exists
    if not users_col.find_one({"username": "admin"}):
        users_col.insert_one({"username": "admin", "password": "admin123"})

    app.run(debug=True,use_reloader = False)

