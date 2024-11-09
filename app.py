from flask import Flask, render_template, request, redirect, url_for, flash, session
import firebase_admin
from firebase_admin import credentials, auth
import pandas as pd
from textblob import TextBlob
import io
import base64
from io import BytesIO
import tempfile
from flask_session import Session  # Import Flask-Session for server-side sessions
import matplotlib.pyplot as plt  # Import for plotting graphs
import matplotlib
from werkzeug.urls import url_quote
matplotlib.use('Agg')

app = Flask(__name__)
app.secret_key = "your_secret_key"

# Set up Flask-Session to use server-side sessions
app.config['SESSION_TYPE'] = 'filesystem'  # Store sessions on the file system
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True  # To protect session from tampering

Session(app)  # Initialize the session extension

# Initialize Firebase Admin SDK
#cred = credentials.Certificate("config/sentianalysis-34005-firebase-adminsdk-mk2e4-7062452989.json")
#firebase_admin.initialize_app(cred)

def initialize_firebase():
    # Path to your Base64-encoded Firebase credentials file
    base64_file_path = "config/firebase_credentials_base64.txt"  # Path to the Base64 credentials file

    # Read the Base64 content from the file with UTF-8 encoding
    try:
        with open(base64_file_path, "r", encoding='utf-8') as file:
            base64_content = file.read().strip()

        # Decode the Base64 content
        decoded_credentials = base64.b64decode(base64_content)

        # Use BytesIO to treat the decoded content as a file-like object
        cred = credentials.Certificate(io.BytesIO(decoded_credentials))
        firebase_admin.initialize_app(cred)
        print("Firebase initialized successfully!")

    except Exception as e:
        print(f"Error initializing Firebase: {str(e)}")

# Initialize Firebase Admin SDK
initialize_firebase()

# Function to classify reviews as Positive, Negative, or Neutral
def analyze_data(data):
    if 'ProductId' not in data.columns or 'Summary' not in data.columns or 'UserId' not in data.columns:
        flash("Dataset is missing required columns ('ProductId', 'Summary', or 'UserId').", "error")
        return None

    data['Sentiment'] = data['Summary'].apply(lambda x: TextBlob(str(x)).sentiment.polarity)
    data['Sentiment_Label'] = data['Sentiment'].apply(
        lambda x: 'Positive' if x > 0 else 'Negative' if x < 0 else 'Neutral'
    )

    session['total_customers'] = len(data)
    return data[['UserId', 'ProductId', 'Summary', 'Sentiment_Label']].to_dict('records')

# Helper function to generate charts as base64 images
def generate_charts(data):
    sentiment_counts = data['Sentiment_Label'].value_counts()
    fig1, ax1 = plt.subplots()
    ax1.pie(sentiment_counts, labels=sentiment_counts.index, autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')
    pie_buffer = BytesIO()
    fig1.savefig(pie_buffer, format='png')
    pie_buffer.seek(0)
    pie_chart_base64 = base64.b64encode(pie_buffer.getvalue()).decode('utf8')

    product_sentiments = data.groupby(['ProductId', 'Sentiment_Label']).size().unstack().fillna(0)
    product_sentiments.plot(kind='bar', stacked=True)
    plt.xlabel('Product ID')
    plt.ylabel('Number of Reviews')
    plt.title('Sentiment Distribution by Product')
    bar_buffer = BytesIO()
    plt.savefig(bar_buffer, format='png')
    bar_buffer.seek(0)
    bar_chart_base64 = base64.b64encode(bar_buffer.getvalue()).decode('utf8')

    return pie_chart_base64, bar_chart_base64

@app.route('/')
def home():
    return redirect(url_for('sign_up'))

@app.route('/sign_up', methods=['GET', 'POST'])
def sign_up():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        mobile = request.form['mobile']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for('sign_up'))

        try:
            user = auth.create_user(
                email=email,
                password=password,
                display_name=username,
                phone_number=mobile
            )
            flash("Account created successfully! Please log in.", "success")
            return redirect(url_for('login'))
        except Exception as e:
            flash(f"Error creating account: {str(e)}", "error")

    return render_template('sign_up.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['username']
        password = request.form['password']

        try:
            user = auth.get_user_by_email(email)
            session['user_id'] = user.uid
            flash("Login successful!", "success")
            return redirect(url_for('upload'))
        except Exception:
            flash("Invalid login credentials or user not found.", "error")

    return render_template('login.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'user_id' not in session:
        flash("You need to log in to upload files.", "error")
        return redirect(url_for('login'))

    if request.method == 'POST':
        file = request.files.get('file')
        if file and (file.filename.endswith('.xlsx') or file.filename.endswith('.csv') or file.filename.endswith('.pdf')):
            try:
                if file.filename.endswith('.xlsx'):
                    data = pd.read_excel(file, engine='openpyxl')
                elif file.filename.endswith('.csv'):
                    data = pd.read_csv(file)
                else:
                    flash("PDF files are not supported for analysis.", "error")
                    return redirect(url_for('upload'))

                data = data.loc[:, ~data.columns.str.contains('^Unnamed')]
                analysis_results = analyze_data(data)

                if analysis_results:
                    # Store the analysis results in a temporary file or database
                    session['analysis_results'] = analysis_results
                    pie_chart_base64, bar_chart_base64 = generate_charts(data)
                    session['pie_chart'] = pie_chart_base64
                    session['bar_chart'] = bar_chart_base64
                    flash("File uploaded and analyzed successfully!", "success")
                    return redirect(url_for('dashboard'))
                else:
                    flash("Failed to analyze the dataset. Please check the format.", "error")
            except Exception as e:
                flash(f"Error processing file: {str(e)}", "error")
        else:
            flash("Please upload a valid Excel, CSV, or PDF file.", "error")
    return render_template('upload.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        flash("You need to log in to access the dashboard.", "error")
        return redirect(url_for('login'))

    analysis_results = session.get('analysis_results')
    if not analysis_results:
        flash("No analysis data available. Please upload a file.", "error")
        return redirect(url_for('upload'))

    pie_chart_base64 = session.get('pie_chart')
    bar_chart_base64 = session.get('bar_chart')

    positive_reviews = [r for r in analysis_results if r['Sentiment_Label'] == 'Positive']
    negative_reviews = [r for r in analysis_results if r['Sentiment_Label'] == 'Negative']
    neutral_reviews = [r for r in analysis_results if r['Sentiment_Label'] == 'Neutral']

    return render_template(
        'dashboard.html',
        reviews=analysis_results,
        total_customers=session.get('total_customers'),
        positive_reviews=positive_reviews,
        negative_reviews=negative_reviews,
        neutral_reviews=neutral_reviews,
        pie_chart=pie_chart_base64,
        bar_chart=bar_chart_base64
    )

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        flash("Please log in to access chat support.", "error")
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        flash("Please log in to access settings.", "error")
        return redirect(url_for('login'))
    return render_template('settings.html')

@app.route('/report')
def report():
    if 'user_id' not in session:
        flash("Please log in to access the report.", "error")
        return redirect(url_for('login'))

    analysis_results = session.get('analysis_results')
    if not analysis_results:
        flash("No report data available. Please upload a file.", "error")
        return redirect(url_for('upload'))

    return render_template('report.html', reviews=analysis_results)

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
