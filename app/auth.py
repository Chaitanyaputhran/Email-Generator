import streamlit as st
import boto3
from botocore.exceptions import ClientError
import hmac
import hashlib
import base64
import os
from dotenv import load_dotenv

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
                'tokens': response['AuthenticationResult']
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
    
    def sign_out(self, access_token):
        """Sign out user"""
        try:
            self.client.global_sign_out(AccessToken=access_token)
            return {'success': True, 'message': 'Signed out successfully'}
        except ClientError as e:
            return {'success': False, 'message': str(e)}
    
    def get_user(self, access_token):
        """Get user information"""
        try:
            response = self.client.get_user(AccessToken=access_token)
            return {'success': True, 'user': response}
        except ClientError as e:
            return {'success': False, 'message': str(e)}


def login_page():
    """Render login page"""
    st.title("🔐 Email Generator - Login")
    
    # Initialize session state
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    if 'access_token' not in st.session_state:
        st.session_state.access_token = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    
    # Create tabs for different auth actions
    tab1, tab2, tab3 = st.tabs(["Login", "Sign Up", "Forgot Password"])
    
    auth = CognitoAuth()
    
    with tab1:
        st.subheader("Login to Your Account")
        with st.form("login_form"):
            username = st.text_input("Username")
            password = st.text_input("Password", type="password")
            submit = st.form_submit_button("Login")
            
            if submit:
                if username and password:
                    result = auth.sign_in(username, password)
                    if result['success']:
                        st.session_state.authenticated = True
                        st.session_state.access_token = result['tokens']['AccessToken']
                        st.session_state.username = username
                        st.success("Login successful!")
                        st.rerun()
                    else:
                        st.error(f"Login failed: {result['message']}")
                else:
                    st.warning("Please enter both username and password")
    
    with tab2:
        st.subheader("Create New Account")
        with st.form("signup_form"):
            new_username = st.text_input("Username", key="signup_username")
            new_email = st.text_input("Email", key="signup_email")
            new_password = st.text_input("Password", type="password", key="signup_password")
            confirm_password = st.text_input("Confirm Password", type="password")
            signup_submit = st.form_submit_button("Sign Up")
            
            if signup_submit:
                if new_username and new_email and new_password and confirm_password:
                    if new_password == confirm_password:
                        result = auth.sign_up(new_username, new_password, new_email)
                        if result['success']:
                            st.success(result['message'])
                            st.info("Please check your email and use the verification tab to confirm your account.")
                        else:
                            st.error(f"Sign up failed: {result['message']}")
                    else:
                        st.error("Passwords do not match")
                else:
                    st.warning("Please fill in all fields")
        
        st.markdown("---")
        st.subheader("Verify Email")
        with st.form("verify_form"):
            verify_username = st.text_input("Username", key="verify_username")
            verification_code = st.text_input("Verification Code")
            verify_submit = st.form_submit_button("Verify")
            
            if verify_submit:
                if verify_username and verification_code:
                    result = auth.confirm_sign_up(verify_username, verification_code)
                    if result['success']:
                        st.success(result['message'])
                    else:
                        st.error(f"Verification failed: {result['message']}")
                else:
                    st.warning("Please enter username and verification code")
    
    with tab3:
        st.subheader("Reset Password")
        with st.form("forgot_password_form"):
            forgot_username = st.text_input("Username", key="forgot_username")
            forgot_submit = st.form_submit_button("Send Reset Code")
            
            if forgot_submit:
                if forgot_username:
                    result = auth.forgot_password(forgot_username)
                    if result['success']:
                        st.success(result['message'])
                    else:
                        st.error(f"Failed: {result['message']}")
                else:
                    st.warning("Please enter your username")
        
        st.markdown("---")
        st.subheader("Confirm Password Reset")
        with st.form("reset_password_form"):
            reset_username = st.text_input("Username", key="reset_username")
            reset_code = st.text_input("Reset Code")
            new_pass = st.text_input("New Password", type="password", key="new_pass")
            confirm_new_pass = st.text_input("Confirm New Password", type="password", key="confirm_new_pass")
            reset_submit = st.form_submit_button("Reset Password")
            
            if reset_submit:
                if reset_username and reset_code and new_pass and confirm_new_pass:
                    if new_pass == confirm_new_pass:
                        result = auth.confirm_forgot_password(reset_username, reset_code, new_pass)
                        if result['success']:
                            st.success(result['message'])
                        else:
                            st.error(f"Password reset failed: {result['message']}")
                    else:
                        st.error("Passwords do not match")
                else:
                    st.warning("Please fill in all fields")


def check_authentication():
    """Check if user is authenticated"""
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
    
    if not st.session_state.authenticated:
        login_page()
        st.stop()
    
    # Show logout button in sidebar
    with st.sidebar:
        st.write(f"👤 Logged in as: **{st.session_state.username}**")
        if st.button("Logout"):
            auth = CognitoAuth()
            if st.session_state.access_token:
                auth.sign_out(st.session_state.access_token)
            st.session_state.authenticated = False
            st.session_state.access_token = None
            st.session_state.username = None
            st.rerun()
