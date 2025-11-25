"""
Standalone Login Page for Email Generator with AWS Cognito Authentication
This page can be used independently to test authentication without the main app
"""

import streamlit as st
import boto3
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class CognitoAuth:
    def __init__(self):
        self.client = boto3.client('cognito-idp', region_name=os.getenv('AWS_REGION', 'us-east-1'))
        self.user_pool_id = os.getenv('COGNITO_USER_POOL_ID')
        self.client_id = os.getenv('COGNITO_CLIENT_ID')
        self.client_secret = os.getenv('COGNITO_CLIENT_SECRET')
    
    def get_secret_hash(self, username):
        """Generate secret hash for Cognito"""
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
    
    def get_user(self, access_token):
        """Get user information"""
        try:
            response = self.client.get_user(AccessToken=access_token)
            return {'success': True, 'user': response}
        except ClientError as e:
            return {'success': False, 'message': str(e)}


def main():
    """Main function to render the standalone login page"""
    
    # Set page configuration
    st.set_page_config(
        page_title="Email Generator - Authentication",
        page_icon="🔐",
        layout="wide",
        initial_sidebar_state="collapsed"
    )
    
    # Custom CSS for better styling
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
        .success-box {
            padding: 1rem;
            border-radius: 0.5rem;
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            color: #155724;
            margin: 1rem 0;
        }
        .error-box {
            padding: 1rem;
            border-radius: 0.5rem;
            background-color: #f8d7da;
            border: 1px solid #f5c6cb;
            color: #721c24;
            margin: 1rem 0;
        }
        .info-box {
            padding: 1rem;
            border-radius: 0.5rem;
            background-color: #d1ecf1;
            border: 1px solid #bee5eb;
            color: #0c5460;
            margin: 1rem 0;
        }
        </style>
    """, unsafe_allow_html=True)
    
    # Header
    st.title("🔐 Email Generator - Authentication Portal")
    st.markdown("---")
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'access_token' not in st.session_state:
        st.session_state.access_token = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    
    # Check if already authenticated
    if st.session_state.authenticated:
        st.success(f"✅ You are logged in as: **{st.session_state.username}**")
        
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.info("🎉 Authentication successful! You can now use the Email Generator app.")
            st.markdown("""
            **Next Steps:**
            1. Run the main application: `python3 -m streamlit run app/main_auth.py`
            2. You will be automatically logged in
            3. Start generating cold emails!
            """)
        
        with col2:
            if st.button("🚪 Logout", use_container_width=True):
                st.session_state.authenticated = False
                st.session_state.access_token = None
                st.session_state.username = None
                st.rerun()
        
        # Display user info
        st.markdown("---")
        st.subheader("👤 User Information")
        auth = CognitoAuth()
        user_info = auth.get_user(st.session_state.access_token)
        if user_info['success']:
            with st.expander("View User Details"):
                st.json(user_info['user'])
        
        return
    
    # Create tabs for different auth actions
    tab1, tab2, tab3, tab4 = st.tabs(["🔑 Login", "📝 Sign Up", "🔄 Forgot Password", "ℹ️ Info"])
    
    auth = CognitoAuth()
    
    # LOGIN TAB
    with tab1:
        st.subheader("Login to Your Account")
        st.markdown("Enter your credentials to access the Email Generator")
        
        with st.form("login_form", clear_on_submit=False):
            username = st.text_input("Username", placeholder="Enter your username")
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
                    st.warning("⚠️ Please enter both username and password")
    
    # SIGN UP TAB
    with tab2:
        st.subheader("Create New Account")
        st.markdown("Join us and start generating professional cold emails")
        
        with st.form("signup_form"):
            new_username = st.text_input("Username", key="signup_username", placeholder="Choose a unique username")
            new_email = st.text_input("Email", key="signup_email", placeholder="your.email@example.com")
            
            col1, col2 = st.columns(2)
            with col1:
                new_password = st.text_input("Password", type="password", key="signup_password", placeholder="Min. 8 characters")
            with col2:
                confirm_password = st.text_input("Confirm Password", type="password", placeholder="Re-enter password")
            
            st.info("💡 **Password Requirements:**\n- Minimum 8 characters\n- At least one uppercase letter\n- At least one lowercase letter\n- At least one number")
            
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
        st.markdown("Enter the verification code sent to your email")
        
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
        st.markdown("Request a password reset code")
        
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
        st.markdown("Enter the reset code and your new password")
        
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
    
    # INFO TAB
    with tab4:
        st.subheader("ℹ️ Information & Help")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🎯 About This App
            
            This is the authentication portal for the **Email Generator** application. 
            The app uses AWS Cognito for secure user authentication.
            
            ### 🔒 Security Features
            
            - ✅ Secure password hashing
            - ✅ Email verification required
            - ✅ Token-based authentication
            - ✅ Password reset capability
            - ✅ AWS Cognito integration
            
            ### 📋 Getting Started
            
            1. **Sign Up**: Create a new account
            2. **Verify**: Check email for verification code
            3. **Login**: Use your credentials to login
            4. **Use App**: Start generating cold emails!
            """)
        
        with col2:
            st.markdown("""
            ### 🐛 Troubleshooting
            
            **"Email not received"**
            - Check your spam folder
            - Wait a few minutes
            - Verify email configuration in Cognito
            
            **"Invalid password"**
            - Must be at least 8 characters
            - Include uppercase, lowercase, and number
            - Check for special character requirements
            
            **"User not confirmed"**
            - Complete email verification first
            - Check verification code from email
            
            ### 📚 Documentation
            
            For complete setup and deployment guide, see:
            - `COMPLETE_AUTH_GUIDE.md`
            
            ### 🔗 Environment Variables Required
            
            ```
            AWS_REGION=us-east-1
            COGNITO_USER_POOL_ID=...
            COGNITO_CLIENT_ID=...
            COGNITO_CLIENT_SECRET=...
            ```
            """)
        
        st.markdown("---")
        st.info("💡 **Tip**: After successful login, run `python3 -m streamlit run app/main_auth.py` to use the full application")


if __name__ == "__main__":
    main()
