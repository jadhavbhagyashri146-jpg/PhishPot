import os
import streamlit as st
import sqlite3
import hashlib
from datetime import datetime
import joblib
import re
from urllib.parse import urlparse


from feature_extraction import (
    extract_features,
    get_domain,
    get_suspicious_reasons,
    get_website_information
)


# =========================================================
# PAGE CONFIG
# =========================================================

st.set_page_config(
    page_title="PhishPot",
    page_icon="🐟",
    layout="wide"
)

# =========================================================
# DATABASE
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)

DB_NAME = os.path.join(
    BASE_DIR,
    "data",
    "phishpot.db"
)


def get_connection():
    return sqlite3.connect(DB_NAME)


def init_database():

    os.makedirs(
        os.path.dirname(DB_NAME),
        exist_ok=True
    )

    conn = get_connection()
    cursor = conn.cursor()

    # Users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            mobile TEXT,
            password TEXT NOT NULL
        )
    """)

    # Check and update old users table
    cursor.execute("PRAGMA table_info(users)")
    columns = [column[1] for column in cursor.fetchall()]

    if "mobile" not in columns:
        cursor.execute(
            "ALTER TABLE users ADD COLUMN mobile TEXT"
        )

    # Scans table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            url TEXT,
            result TEXT,
            risk TEXT,
            reason TEXT,
            scan_date TEXT,
            scan_time TEXT
        )
    """)

    conn.commit()
    conn.close()


init_database()
def hash_password(password):
    return hashlib.sha256(
        password.encode()
    ).hexdigest()

# =========================================================
# LOAD MODEL
# =========================================================


MODEL_PATH = os.path.join(
    BASE_DIR,
    "models",
    "phishing_model.joblib"
)

@st.cache_resource
def load_model():
    return joblib.load(MODEL_PATH)


model = load_model()


# =========================================================
# SESSION
# =========================================================

if "logged_in" not in st.session_state:

    st.session_state.logged_in = False


if "user_email" not in st.session_state:

    st.session_state.user_email = ""


if "user_name" not in st.session_state:

    st.session_state.user_name = ""


# =========================================================
# CSS
# =========================================================

st.markdown("""
<style>

.main-title {
    text-align: center;
    font-size: 55px;
    font-weight: 800;
}

.subtitle {
    text-align: center;
    font-size: 20px;
}

.safe {
    padding: 25px;
    border-radius: 15px;
    background-color: #e8f5e9;
}

.warning {
    padding: 25px;
    border-radius: 15px;
    background-color: #ffebee;
}

.card {
    padding: 20px;
    border-radius: 15px;
    border: 1px solid #dddddd;
}

</style>
""", unsafe_allow_html=True)


# =========================================================
# URL VALIDATION
# =========================================================

def valid_url(url):

    try:

        if not url.startswith(
            ("http://", "https://")
        ):
            url = "http://" + url

        parsed = urlparse(url)

        return bool(
            parsed.netloc
            and "." in parsed.netloc
        )

    except:

        return False


# =========================================================
# RISK LEVEL
# =========================================================

def get_risk_level(phishing_probability):

    if phishing_probability < 0.25:

        return "Low Risk", "🟢"

    elif phishing_probability < 0.50:

        return "Medium Risk", "🟡"

    elif phishing_probability < 0.75:

        return "High Risk", "🟠"

    else:

        return "Critical Risk", "🔴"


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    email,
    url,
    result,
    risk,
    reason
):

    now = datetime.now()

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO scans
        (
            email,
            url,
            result,
            risk,
            reason,
            scan_date,
            scan_time
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        email,
        url,
        result,
        risk,
        reason,
        now.strftime("%Y-%m-%d"),
        now.strftime("%H:%M:%S")
    ))

    conn.commit()

    conn.close()


# =========================================================
# LOGIN / REGISTER
# =========================================================

def authentication_page():

    st.markdown(
        '<div class="main-title"> PhishPot</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'ML-Based Phishing URL Risk Assessment System'
        '</div>',
        unsafe_allow_html=True
    )

    st.write("")

    tab1, tab2 = st.tabs(
        ["🔐 Login", "📝 Register"]
    )


    # -----------------------------------------------------
    # LOGIN
    # -----------------------------------------------------

    with tab1:

        st.subheader("Login")

        email = st.text_input(
            "Email",
            key="login_email"
        )

        password = st.text_input(
            "Password",
            type="password",
            key="login_password"
        )

        if st.button(
            "Login",
            use_container_width=True
        ):

            conn = get_connection()

            cursor = conn.cursor()

            cursor.execute(
                """
                SELECT name
                FROM users
                WHERE email = ?
                AND password = ?
                """,
                (
                    email,
                    hash_password(password)
                )
            )

            user = cursor.fetchone()

            conn.close()

            if user:

                st.session_state.logged_in = True
                st.session_state.user_email = email
                st.session_state.user_name = user[0]

                st.success(
                    "Login successful!"
                )

                st.rerun()

            else:

                st.error(
                    "Invalid email or password."
                )


    # -----------------------------------------------------
    # REGISTER
    # -----------------------------------------------------

    with tab2:

        st.subheader("Create Account")

        name = st.text_input(
            "Name",
            key="register_name"
        )

        email = st.text_input(
            "Email Address",
            key="register_email"
        )

        mobile = st.text_input(
            "Mobile Number",
            key="register_mobile"
        )

        password = st.text_input(
            "Password",
            type="password",
            key="register_password"
        )

        confirm = st.text_input(
            "Confirm Password",
            type="password"
        )

        if st.button(
            "Create Account",
            use_container_width=True
        ):

            if not name or not email or not mobile or not password:

                st.warning(
                    "Please fill all required fields."
                )

            elif password != confirm:

                st.error(
                    "Passwords do not match."
                )

            else:

                try:

                    conn = get_connection()

                    cursor = conn.cursor()

                    cursor.execute(
                        """
                        INSERT INTO users
                        (name, email, mobile, password)
                        VALUES (?, ?, ?, ?)
                        """,
                        (
                            name,
                            email,
                            mobile,
                            hash_password(password)
                        )
                    )

                    conn.commit()

                    conn.close()

                    st.success(
                        "Registration successful! "
                        "Please login."
                    )

                except sqlite3.IntegrityError:

                    st.error(
                        "This email is already registered."
                    )


# =========================================================
# HOME
# =========================================================

def home_page():

    st.markdown(
        '<div class="main-title">🛡️ PhishPot</div>',
        unsafe_allow_html=True
    )

    st.markdown(
        '<div class="subtitle">'
        'ML-Based Phishing URL Risk Assessment System'
        '</div>',
        unsafe_allow_html=True
    )

    st.write("")

    st.success(
        f"Welcome, {st.session_state.user_name}! 👋"
    )

    st.header("How It Works")

    col1, col2, col3, col4 = st.columns(4)

    with col1:

        st.info(
            "🔗\n\n"
            "**1. Paste URL**\n\n"
            "Enter the website URL you want to check."
        )

    with col2:

        st.info(
            "🔍\n\n"
            "**2. Scan & Detect**\n\n"
            "The ML model analyzes URL-related features."
        )

    with col3:

        st.info(
            "🛡️\n\n"
            "**3. Take Action**\n\n"
            "Get safety guidance based on the result."
        )

    with col4:

        st.info(
            "✅\n\n"
            "**4. Stay Safe**\n\n"
            "Avoid sharing sensitive information on suspicious sites."
        )

    st.write("")

    st.markdown(
        """
        ### 🔎 Scan a website

        Use **Scan URL** from the menu to check a website.
        """
    )

    st.markdown(
        """
        <br>
        <h3 style='text-align:center;'>
        “We've tied the knot. Let's stay safe with PhishPot.”
        </h3>
        """,
        unsafe_allow_html=True
    )


# =========================================================
# SCAN PAGE
# =========================================================

def scan_page():

    st.title("🔎 Scan URL")

    st.write(
        "Enter a website URL and PhishPot will analyze it."
    )

    url = st.text_input(
        "Enter Website URL",
        placeholder="https://example.com"
    )

    if st.button(
        "🔍 Spot, Is It Phishing or Not?",
        use_container_width=True
    ):

        # -------------------------------------------------
        # EMPTY URL
        # -------------------------------------------------

        if not url:

            st.warning(
                "Please enter a URL."
            )

            return

        # -------------------------------------------------
        # URL VALIDATION
        # -------------------------------------------------

        if not valid_url(url):

            st.error(
                "⚠️ Invalid URL\n\n"
                "Please enter a valid website URL."
            )

            return

        # -------------------------------------------------
        # ANALYSIS
        # -------------------------------------------------

        with st.spinner(
            "Analyzing URL..."
        ):

            features = extract_features(url)

            prediction = model.predict(
                [features]
            )[0]

            probabilities = model.predict_proba(
                [features]
            )[0]

            classes = list(
                model.classes_
            )

            phishing_probability = 0

            if -1 in classes:

                phishing_index = classes.index(-1)

                phishing_probability = probabilities[
                    phishing_index
                ]

            risk, icon = get_risk_level(
                phishing_probability
            )

            confidence = max(
                probabilities
            )

            reasons = get_suspicious_reasons(
                url
            )

        # =================================================
        # PHISHING RESULT
        # =================================================

        if prediction == -1:

            st.markdown(
                '<div class="warning">',
                unsafe_allow_html=True
            )

            st.error(
                "🔴 PHISHING DETECTED"
            )

            st.markdown(
                f"### {icon} {risk}"
            )

            st.progress(
                float(confidence)
            )

            st.write(
                f"Model confidence: "
                f"**{confidence * 100:.2f}%**"
            )

            st.markdown(
                "</div>",
                unsafe_allow_html=True
            )

            # ---------------------------------------------
            # WHY SUSPICIOUS
            # ---------------------------------------------

            st.subheader(
                "⚠️ Why is this URL suspicious?"
            )

            if reasons:

                for reason in reasons:

                    st.write(
                        "• " + reason
                    )

            else:

                st.write(
                    "The model identified this URL "
                    "as potentially phishing based on "
                    "the extracted feature pattern."
                )

            # ---------------------------------------------
            # SAFETY GUIDANCE
            # ---------------------------------------------

            st.subheader(
                "🛡️ What Should You Do?"
            )

            st.warning(
                """
                🚫 If you have NOT opened this link:

                • Do not open the suspicious link.
                • Do not enter your username, password or OTP.
                • Do not provide banking or card details.
                • Do not download any files from this link.
                • Delete or report the message/email containing the link.
                """
            )

            st.error(
                """
                ⚠️ If you have ALREADY opened the link:

                • Close the webpage immediately.
                • Do not enter any personal or financial information.
                • Do not download or install anything.
                • Run a security scan on your device.
                """
            )

            st.info(
                """
                🔐 If you entered your password or OTP:

                • Change your password immediately using the official website/app.
                • Enable two-factor authentication (2FA).
                • Check your account for suspicious activity.
                """
            )

            st.info(
                """
                💳 If you entered banking or card details:

                • Contact your bank immediately.
                • Block or freeze the affected card if required.
                • Check your recent transactions for unauthorized activity.
                """
            )

            result_text = "Phishing"

            if reasons:

                reason_text = "; ".join(
                    reasons
                )

            else:

                reason_text = (
                    "The model identified this URL "
                    "as potentially phishing."
                )

        # =================================================
        # LEGITIMATE RESULT
        # =================================================

        else:

            st.markdown(
                '<div class="safe">',
                unsafe_allow_html=True
            )

            st.success(
                "🟢 No Phishing Risk Detected"
            )

            st.markdown(
                f"### 🟢 {risk}"
            )

            st.progress(
                float(confidence)
            )

            st.write(
                f"Model confidence: "
                f"**{confidence * 100:.2f}%**"
            )

            st.markdown(
                "</div>",
                unsafe_allow_html=True
            )

            # ---------------------------------------------
            # WEBSITE INFORMATION
            # ---------------------------------------------

           
            st.subheader(
                "🌐 Website Information"
            )

            st.write(
                "The URL was classified as "
                "**legitimate by the trained model.**"
            )

            st.write(
                f"**URL:** {url}"
            )

            website_info = get_website_information(url)

            st.write(
                f"**Website Name:** {website_info['name']}"
            )

            st.write(
                f"**Website Type:** {website_info['type']}"
            )

            st.write(
                f"**About:** {website_info['description']}"
            )

            st.link_button(
                "🌐 Visit Website",
                url
            )

            result_text = "Legitimate"

            reason_text = (
                "No major suspicious URL indicators detected."
            )
            st.link_button(
                "🌐 Visit Website",
                url
            )

            result_text = "Legitimate"

            reason_text = (
                "No major suspicious URL indicators detected."
            )

        # =================================================
        # SAVE SCAN HISTORY
        # =================================================

        save_scan(
            st.session_state.user_email,
            url,
            result_text,
            risk,
            reason_text
        )





# =========================================================
# HISTORY
# =========================================================

def history_page():

    st.title("📋 Scan History")

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(
        """
        SELECT url, result, risk, reason,
               scan_date, scan_time
        FROM scans
        WHERE email = ?
        ORDER BY id DESC
        """,
        (
            st.session_state.user_email,
        )
    )

    records = cursor.fetchall()

    conn.close()

    if not records:

        st.info(
            "No scans found yet."
        )

        return

    for record in records:

        url, result, risk, reason, date, time = record

        with st.expander(
            f"{'🔴' if result == 'Phishing' else '🟢'} "
            f"{result} — {url}"
        ):

            st.write(
                f"**Risk Level:** {risk}"
            )

            st.write(
                f"**Why Suspicious:** {reason}"
            )

            st.write(
                f"**Scan Date:** {date}"
            )

            st.write(
                f"**Scan Time:** {time}"
            )


# =========================================================
# HOW IT WORKS
# =========================================================

def how_it_works_page():

    st.title("⚙️ How It Works")

    st.write(
        """
        PhishPot uses a supervised machine learning
        classification model to analyze URL-related
        features.
        """
    )

    st.markdown(
        """
        ### Step 1 — Paste URL 🔗

        The user enters a website URL.

        ### Step 2 — Feature Extraction 🔍

        PhishPot extracts URL and webpage-related
        characteristics.

        ### Step 3 — Random Forest Model 🤖

        The extracted feature vector is passed to
        the trained Random Forest classifier.

        ### Step 4 — Prediction 🎯

        The model predicts whether the website is
        phishing or legitimate.

        ### Step 5 — Safety Guidance 🛡️

        Phishing results show suspicious indicators
        and recommended safety actions.
        """
    )


# =========================================================
# PROFILE
# =========================================================

def profile_page():

    st.title("👤 Profile")

    st.write(
        f"**Name:** {st.session_state.user_name}"
    )

    st.write(
        f"**Email Address:** "
        f"{st.session_state.user_email}"
    )

    st.write(
        "**Password:** ••••••••"
    )

    st.write("")

    if st.button(
        "Logout",
        use_container_width=True
    ):

        st.session_state.logged_in = False
        st.session_state.user_email = ""
        st.session_state.user_name = ""

        st.rerun()


# =========================================================
# MAIN APPLICATION
# =========================================================

if not st.session_state.logged_in:

    authentication_page()

else:

    st.sidebar.title("🐟 PhishPot")

    st.sidebar.write(
        f"Welcome, {st.session_state.user_name}"
    )

    menu = st.sidebar.radio(
        "Menu",
        [
            "Home",
            "Scan URL",
            "Scan History",
            "How It Works",
            "Profile",
            "Logout"
        ]
    )

    if menu == "Home":

        home_page()

    elif menu == "Scan URL":

        scan_page()

    elif menu == "Scan History":

        history_page()

    elif menu == "How It Works":

        how_it_works_page()

    elif menu == "Profile":

        profile_page()

    elif menu == "Logout":

        st.session_state.logged_in = False

        st.session_state.user_email = ""
        st.session_state.user_name = ""

        st.rerun()
        
        