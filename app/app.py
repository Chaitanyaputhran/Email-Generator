"""
Email Generator with AWS Cognito Authentication - Single Unified Application
This combines authentication and email generation in one app
"""

import streamlit as st
from langchain_community.document_loaders import WebBaseLoader
import boto3
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
import os
import warnings
from dotenv import load_dotenv
from chains import Chain
from portfolio import Portfolio
from utils import clean_text

# Suppress warnings
warnings.filterwarnings('ignore')
os.environ['USER_AGENT'] = 'EmailGenerator/1.0'

# Load environment variables
load_dotenv()


class CognitoAuth:
    def __init__(self):
        self.aws_region = os.getenv('AWS_REGION', 'us-east-1')
        self.user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
        self.client_id = os.getenv('COGNITO_CLIENT_ID')
        self.client_secret = os.getenv('COGNITO_CLIENT_SECRET')
        
        # Check if Cognito credentials are configured
        self.is_configured = all([
            self.user_pool_id and self.user_pool_id != 'your_user_pool_id_here',
            self.client_id and self.client_id != 'your_client_id_here',
            self.client_secret and self.client_secret != 'your_client_secret_here'
        ])
        
        if self.is_configured:
            # Create boto3 client without checking credentials first
            self.client = boto3.client('cognito-idp', region_name=self.aws_region)
            self.connection_error = None
        else:
            self.client = None
            self.connection_error = None
    
    def get_secret_hash(self, username):
        """Generate secret hash for Cognito"""
        if not self.client_secret:
            return None
        message = bytes(username + self.client_id, 'utf-8')
        secret = bytes(self.client_secret, 'utf-8')
        dig = hmac.new(secret, msg=message, digestmod=hashlib.sha256).digest()
        return base64.b64encode(dig).decode()
    
    def sign_up(self, username, password, email):
        """Register a new user"""
        try:
            response = self.client.sign_up(
                ClientId=self.client_id,
                SecretHash=self.get_secret_hash(username),
                Username=username,
                Password=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email}
                ]
            )
            return {'success': True, 'message': 'Registration successful! Please check your email for verification code.'}
        except ClientError as e:
            return {'success': False, 'message': str(e)}
    
    def confirm_sign_up(self, username, confirmation_code):
        """Confirm user registration with verification code"""
        try:
            self.client.confirm_sign_up(
                ClientId=self.client_id,
                SecretHash=self.get_secret_hash(username),
                Username=username,
                ConfirmationCode=confirmation_code
            )
            return {'success': True, 'message': 'Email verified successfully! You can now log in.'}
        except ClientError as e:
            return {'success': False, 'message': str(e)}
    
    def sign_in(self, username, password):
        """Sign in user"""
        try:
            response = self.client.initiate_auth(
                ClientId=self.client_id,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': self.get_secret_hash(username)
                }
            )
            return {
                'success': True,
                'tokens': response['AuthenticationResult'],
                'message': 'Login successful!'
            }
        except ClientError as e:
            return {'success': False, 'message': str(e)}
    
    def forgot_password(self, username):
        """Initiate forgot password flow"""
        try:
            self.client.forgot_password(
                ClientId=self.client_id,
                SecretHash=self.get_secret_hash(username),
                Username=username
            )
            return {'success': True, 'message': 'Password reset code sent to your email.'}
        except ClientError as e:
            return {'success': False, 'message': str(e)}
    
    def confirm_forgot_password(self, username, confirmation_code, new_password):
        """Confirm password reset"""
        try:
            self.client.confirm_forgot_password(
                ClientId=self.client_id,
                SecretHash=self.get_secret_hash(username),
                Username=username,
                ConfirmationCode=confirmation_code,
                Password=new_password
            )
            return {'success': True, 'message': 'Password reset successful! You can now log in.'}
        except ClientError as e:
            return {'success': False, 'message': str(e)}


def render_login_page():
    """Render the login/authentication page"""
    
    # Custom CSS
    st.markdown("""
        <style>
        .main {
            padding: 2rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 2rem;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding: 0 2rem;
            font-size: 1.1rem;
        }
        </style>
    """, unsafe_allow_html=True)
    
    st.title("🔐 Email Generator - Authentication")
    
    # Check AWS Cognito configuration
    auth = CognitoAuth()
    
    if not auth.is_configured:
        st.error("⚠️ **AWS Cognito Not Configured**")
        st.warning("""
        **Authentication is not set up yet.** Please configure AWS Cognito credentials in the `.env` file:
        
        1. Open `Email-Generator/app/.env` file
        2. Add your AWS Cognito credentials:
           - `COGNITO_USER_POOL_ID`
           - `COGNITO_CLIENT_ID`
           - `COGNITO_CLIENT_SECRET`
        
        📚 **For detailed setup instructions, see:** `COMPLETE_AUTH_GUIDE.md`
        
        ⏱️ Setup takes approximately 15 minutes.
        """)
        st.info("💡 **Tip:** Once configured, refresh this page to start using authentication.")
        st.stop()
    
    st.markdown("**Please login or create an account to continue**")
    st.markdown("---")
    
    # Create tabs for different auth actions
    tab1, tab2, tab3 = st.tabs(["🔑 Login", "📝 Sign Up", "🔄 Forgot Password"])
    
    # LOGIN TAB
    with tab1:
        st.subheader("Login to Your Account")
        
        with st.form("login_form"):
            username = st.text_input("Username or Email", placeholder="Enter your username or email")
            password = st.text_input("Password", type="password", placeholder="Enter your password")
            
            col1, col2 = st.columns([1, 1])
            with col1:
                submit = st.form_submit_button("🔓 Login", use_container_width=True)
            with col2:
                clear = st.form_submit_button("🗑️ Clear", use_container_width=True)
            
            if submit:
                if username and password:
                    with st.spinner("Authenticating..."):
                        result = auth.sign_in(username, password)
                        if result['success']:
                            st.session_state.authenticated = True
                            st.session_state.access_token = result['tokens']['AccessToken']
                            st.session_state.username = username
                            st.success("✅ " + result['message'])
                            st.balloons()
                            st.rerun()
                        else:
                            st.error(f"❌ Login failed: {result['message']}")
                else:
                    st.warning("⚠️ Please enter both username/email and password")
    
    # SIGN UP TAB
    with tab2:
        st.subheader("Create New Account")
        
        with st.form("signup_form"):
            new_username = st.text_input("Username", key="signup_username", placeholder="Choose a unique username")
            new_email = st.text_input("Email", key="signup_email", placeholder="your.email@example.com")
            
            col1, col2 = st.columns(2)
            with col1:
                new_password = st.text_input("Password", type="password", key="signup_password", placeholder="Min. 8 characters")
            with col2:
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
            
            st.info("💡 **Password Requirements:** Min. 8 characters, uppercase, lowercase, and number")
            
            signup_submit = st.form_submit_button("📝 Create Account", use_container_width=True)
            
            if signup_submit:
                if new_username and new_email and new_password and confirm_password:
                    if new_password == confirm_password:
                        if len(new_password) >= 8:
                            with st.spinner("Creating account..."):
                                result = auth.sign_up(new_username, new_password, new_email)
                                if result['success']:
                                    st.success("✅ " + result['message'])
                                    st.info("📧 Please check your email and use the verification section below.")
                                else:
                                    st.error(f"❌ Sign up failed: {result['message']}")
                        else:
                            st.error("❌ Password must be at least 8 characters long")
                    else:
                        st.error("❌ Passwords do not match")
                else:
                    st.warning("⚠️ Please fill in all fields")
        
        st.markdown("---")
        st.subheader("✉️ Verify Email")
        
        with st.form("verify_form"):
            verify_username = st.text_input("Username", key="verify_username", placeholder="Your username")
            verification_code = st.text_input("Verification Code", placeholder="6-digit code from email")
            verify_submit = st.form_submit_button("✅ Verify", use_container_width=True)
            
            if verify_submit:
                if verify_username and verification_code:
                    with st.spinner("Verifying..."):
                        result = auth.confirm_sign_up(verify_username, verification_code)
                        if result['success']:
                            st.success("✅ " + result['message'])
                            st.info("👉 You can now login using the Login tab")
                        else:
                            st.error(f"❌ Verification failed: {result['message']}")
                else:
                    st.warning("⚠️ Please enter username and verification code")
    
    # FORGOT PASSWORD TAB
    with tab3:
        st.subheader("Reset Password")
        
        with st.form("forgot_password_form"):
            forgot_username = st.text_input("Username", key="forgot_username", placeholder="Enter your username")
            forgot_submit = st.form_submit_button("📧 Send Reset Code", use_container_width=True)
            
            if forgot_submit:
                if forgot_username:
                    with st.spinner("Sending reset code..."):
                        result = auth.forgot_password(forgot_username)
                        if result['success']:
                            st.success("✅ " + result['message'])
                            st.info("📧 Check your email and use the form below to reset your password")
                        else:
                            st.error(f"❌ Failed: {result['message']}")
                else:
                    st.warning("⚠️ Please enter your username")
        
        st.markdown("---")
        st.subheader("🔐 Confirm Password Reset")
        
        with st.form("reset_password_form"):
            reset_username = st.text_input("Username", key="reset_username", placeholder="Your username")
            reset_code = st.text_input("Reset Code", placeholder="Code from email")
            
            col1, col2 = st.columns(2)
            with col1:
                new_pass = st.text_input("New Password", type="password", key="new_pass", placeholder="Min. 8 characters")
            with col2:
                confirm_new_pass = st.text_input("Confirm New Password", type="password", key="confirm_new_pass", placeholder="Re-enter password")
            
            reset_submit = st.form_submit_button("🔄 Reset Password", use_container_width=True)
            
            if reset_submit:
                if reset_username and reset_code and new_pass and confirm_new_pass:
                    if new_pass == confirm_new_pass:
                        if len(new_pass) >= 8:
                            with st.spinner("Resetting password..."):
                                result = auth.confirm_forgot_password(reset_username, reset_code, new_pass)
                                if result['success']:
                                    st.success("✅ " + result['message'])
                                    st.info("👉 You can now login with your new password")
                                else:
                                    st.error(f"❌ Password reset failed: {result['message']}")
                        else:
                            st.error("❌ Password must be at least 8 characters long")
                    else:
                        st.error("❌ Passwords do not match")
                else:
                    st.warning("⚠️ Please fill in all fields")


def render_resume_upload_ui(s3_manager, username):
    """Render resume upload interface for first-time users"""
    st.title("📄 Upload Your Resume")
    st.markdown("**Welcome! Please upload your resume to get started.**")
    st.markdown("Your resume will be used to personalize job application emails based on your skills and experience.")
    st.markdown("---")
    
    uploaded_file = st.file_uploader(
        "Choose your resume file",
        type=['pdf', 'docx', 'doc', 'txt'],
        help="Supported formats: PDF, DOCX, DOC, TXT"
    )
    
    if uploaded_file is not None:
        st.success(f"✅ File selected: {uploaded_file.name}")
        st.info(f"📊 File size: {uploaded_file.size / 1024:.2f} KB")
        
        col1, col2 = st.columns([1, 1])
        with col1:
            if st.button("📤 Upload Resume", use_container_width=True):
                with st.spinner("Uploading your resume..."):
                    file_content = uploaded_file.read()
                    file_type = uploaded_file.name.split('.')[-1]
                    
                    result = s3_manager.upload_resume(
                        username=username,
                        file_content=file_content,
                        file_name=uploaded_file.name,
                        file_type=file_type
                    )
                    
                    if result['success']:
                        st.success("✅ " + result['message'])
                        st.balloons()
                        st.info("🔄 Redirecting to email generator...")
                        st.session_state.resume_uploaded = True
                        st.rerun()
                    else:
                        st.error("❌ " + result['message'])
        
        with col2:
            if st.button("⏭️ Skip for Now", use_container_width=True):
                st.session_state.resume_uploaded = True
                st.info("You can upload your resume later from the sidebar.")
                st.rerun()
    
    st.markdown("---")
    st.markdown("""
    ### 💡 Why Upload Your Resume?
    - **Personalized Emails**: Generate emails tailored to your actual skills and experience
    - **Better Matches**: Our AI will match your profile with job requirements
    - **Save Time**: No need to manually enter your skills each time
    - **Secure Storage**: Your resume is securely stored in AWS S3
    """)


def render_email_generator(llm, portfolio, s3_manager, username):
    """Render the email generator interface"""
    
    # Show user info and resume management in sidebar
    with st.sidebar:
        st.markdown("### 👤 User Info")
        st.write(f"**Username:** {username}")
        
        st.markdown("---")
        st.markdown("### 📄 Resume Management")
        
        # Check if user has uploaded resume
        has_resume = s3_manager.check_user_has_resume(username) if s3_manager.is_configured else False
        
        if has_resume:
            st.success("✅ Resume uploaded")
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔄 Update", use_container_width=True):
                    st.session_state.show_resume_update = True
                    st.rerun()
            with col2:
                if st.button("🗑️ Delete", use_container_width=True):
                    result = s3_manager.delete_resume(username)
                    if result['success']:
                        st.success("✅ Resume deleted")
                        st.session_state.resume_uploaded = False
                        st.rerun()
                    else:
                        st.error("❌ " + result['message'])
        else:
            st.warning("⚠️ No resume uploaded")
            if st.button("📤 Upload Resume", use_container_width=True):
                st.session_state.show_resume_update = True
                st.rerun()
        
        st.markdown("---")
        if st.button("🚪 Logout", use_container_width=True):
            st.session_state.authenticated = False
            st.session_state.access_token = None
            st.session_state.username = None
            st.session_state.resume_uploaded = False
            st.rerun()
        
        st.markdown("---")
        st.markdown("""
        ### 📖 How to Use
        1. Upload your resume (if not done)
        2. Enter a job posting URL
        3. Click Generate Email
        4. Get personalized email
        5. Copy and customize!
        """)
    
    st.title("📧 Cold Mail Generator")
    st.markdown("**Generate personalized cold emails for job applications**")
    st.markdown("---")
    
    url_input = st.text_input("Enter a Job Posting URL:", value="https://jobs.nike.com/job/R-33460", placeholder="https://example.com/job/...")
    
    # Initialize email_generated state if not exists
    if 'email_generated' not in st.session_state:
        st.session_state.email_generated = False
    
    col1, col2 = st.columns([2, 1])
    with col1:
        submit_button = st.button("🚀 Generate Email", use_container_width=True)
    with col2:
        send_mail_button = st.button("📧 Send Mail", use_container_width=True, disabled=not st.session_state.email_generated)
    
    if send_mail_button:
        if st.session_state.email_generated:
            st.success("✅ Mail sent successfully!")
            st.info("📧 Email has been sent (check your email client or logs)")
        else:
            st.warning("⚠️ Please generate an email first before sending")

    if submit_button:
        if url_input:
            try:
                # Reset email_generated state when generating new email
                st.session_state.email_generated = False
                
                with st.spinner("🔍 Analyzing job posting..."):
                    loader = WebBaseLoader([url_input])
                    data = clean_text(loader.load().pop().page_content)
                
                with st.spinner("💼 Loading portfolio..."):
                    portfolio.load_portfolio()
                
                with st.spinner("🤖 Extracting job requirements..."):
                    jobs = llm.extract_jobs(data)
                
                for job in jobs:
                    skills = job.get('skills', [])
                    links = portfolio.query_links(skills)
                    
                    # Get user's resume summary for personalization
                    user_info = portfolio.get_resume_summary()
                    
                    with st.spinner("✍️ Writing personalized email..."):
                        email = llm.write_mail(job, links, user_info)
                    
                    st.markdown("---")
                    st.subheader("📨 Generated Email")
                    st.code(email, language='markdown')
                    
                    # Add copy button hint
                    st.info("💡 Tip: Click the copy icon in the top-right corner of the code block to copy the email")
                    
                    # Show resume status
                    if user_info:
                        st.success("✅ Email personalized using your resume")
                    else:
                        st.info("ℹ️ Email generated using default portfolio (upload resume for better personalization)")
                
                # Enable Send Mail button after email is generated
                st.success("✅ Email generated successfully!")
                st.session_state.email_generated = True
                    
            except Exception as e:
                st.error(f"❌ An Error Occurred: {e}")
                st.info("Please check the URL and try again")
        else:
            st.warning("⚠️ Please enter a job posting URL")


def main():
    """Main application logic"""
    
    # Set page configuration
    st.set_page_config(
        page_title="Email Generator - AWS Cognito",
        page_icon="📧",
        layout="wide",
        initial_sidebar_state="expanded",
        menu_items={
            'Get Help': None,
            'Report a bug': None,
            'About': None
        }
    )
    
    # Custom CSS for better styling and hiding deploy button
    st.markdown("""
        <style>
        .main {
            padding: 2rem;
        }
        .stTabs [data-baseweb="tab-list"] {
            gap: 2rem;
        }
        .stTabs [data-baseweb="tab"] {
            height: 50px;
            padding: 0 2rem;
            font-size: 1.1rem;
        }
        /* Hide deploy button */
        .stDeployButton {
            visibility: hidden;
        }
        /* Hide the entire toolbar in top right */
        header[data-testid="stHeader"] > div:nth-child(2) {
            display: none;
        }
        /* Alternative: Hide just the deploy button */
        button[kind="header"] {
            display: none;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'access_token' not in st.session_state:
        st.session_state.access_token = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'resume_uploaded' not in st.session_state:
        st.session_state.resume_uploaded = False
    if 'show_resume_update' not in st.session_state:
        st.session_state.show_resume_update = False
    
    # Check authentication status
    if not st.session_state.authenticated:
        # Show login page
        render_login_page()
    else:
        # User is authenticated
        from s3_manager import S3Manager
        
        username = st.session_state.username
        s3_manager = S3Manager()
        chain = Chain()
        
        # Initialize portfolio with username and LLM
        portfolio = Portfolio(username=username, llm=chain.llm)
        
        # Check if showing resume update modal
        if st.session_state.show_resume_update:
            render_resume_upload_ui(s3_manager, username)
            if st.button("← Back to Email Generator"):
                st.session_state.show_resume_update = False
                st.rerun()
        else:
            # Check if user needs to upload resume (first-time user)
            if s3_manager.is_configured and not st.session_state.resume_uploaded:
                has_resume = s3_manager.check_user_has_resume(username)
                if not has_resume:
                    # Show resume upload for first-time users
                    render_resume_upload_ui(s3_manager, username)
                else:
                    # User has resume, proceed to email generator
                    st.session_state.resume_uploaded = True
                    render_email_generator(chain, portfolio, s3_manager, username)
            else:
                # Show email generator
                render_email_generator(chain, portfolio, s3_manager, username)


if __name__ == "__main__":
    main()
