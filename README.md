# 📧 Cold Mail Generator with AWS Cognito Authentication

A cold email generator for services companies using Groq, LangChain, and Streamlit with AWS Cognito authentication. The tool extracts job listings from company career pages and generates personalized cold emails with relevant portfolio links.

## 🎯 Features

- **AWS Cognito Authentication** - Secure user login and registration
- **Smart Email Generation** - AI-powered personalized cold emails
- **Job Listing Extraction** - Automated parsing of career pages
- **Portfolio Matching** - Vector database for relevant portfolio links
- **Login with Username or Email** - Flexible authentication options
- **Password Reset** - Self-service password recovery

## 📋 Use Case

**Scenario:** Nike needs a Principal Software Engineer. Atliq, a software development company, can provide dedicated engineers. Mohan (Business Development Executive at Atliq) uses this tool to generate personalized cold emails to Nike's hiring team.

![Application Demo](imgs/img.png)

## 🏗️ Architecture

![Architecture Diagram](imgs/architecture.png)

## 🚀 Quick Start

### Prerequisites

- Python 3.9 or higher
- AWS Account with Cognito User Pool configured
- Groq API Key

### 1. Clone the Repository

```bash
git clone https://github.com/Chaitanyaputhran/Email-Generator.git
cd Email-Generator
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure Environment Variables

Create a `.env` file in the `app/` directory:

```bash
# app/.env

# Groq API Key (Get from: https://console.groq.com/keys)
GROQ_API_KEY=your_groq_api_key_here

# AWS Cognito Configuration
AWS_REGION=your_aws_region
COGNITO_USER_POOL_ID=your_user_pool_id
COGNITO_CLIENT_ID=your_client_id
COGNITO_CLIENT_SECRET=your_client_secret
```

### 4. Configure AWS Cognito

#### Create Cognito User Pool:

1. Go to **AWS Console** → **Cognito** → **Create User Pool**
2. Configure sign-in options:
   - ✅ Email
   - ✅ Username
3. Configure security requirements (password policy)
4. Enable self-registration
5. Create app client with these settings:
   - **Authentication flows:**
     - ✅ ALLOW_USER_PASSWORD_AUTH
     - ✅ ALLOW_REFRESH_TOKEN_AUTH
     - ✅ ALLOW_USER_SRP_AUTH
   - Generate client secret: ✅ Yes

6. Copy the credentials:
   - User Pool ID
   - App Client ID
   - App Client Secret
   - Region

### 5. Run the Application

#### Option A: With Authentication (Recommended)

```bash
streamlit run app/app.py
```

#### Option B: Without Authentication (Testing)

```bash
streamlit run app/main.py
```

The application will be available at: `http://localhost:8501`

## 📖 Usage Guide

### First Time Setup:

1. **Register Account:**
   - Click "Sign Up" tab
   - Enter username, email, and password
   - Check email for verification code
   - Verify your email

2. **Login:**
   - Use username or email
   - Enter password
   - Click "Login"

3. **Generate Cold Email:**
   - Enter a job posting URL (e.g., https://jobs.nike.com/job/R-33460)
   - Click "Generate Email"
   - Copy the generated email

### Password Reset:

1. Click "Forgot Password" tab
2. Enter your username
3. Check email for reset code
4. Enter code and new password

## ⚙️ Configuration

### Portfolio Management

Edit `app/resource/my_portfolio.csv` to customize your portfolio links:

```csv
Techstack,Links
React,https://example.com/react-portfolio
Python,https://example.com/python-portfolio
Machine Learning,https://example.com/ml-portfolio
```

### Groq API

Get your API key from: https://console.groq.com/keys

Supported models:
- `llama-3.1-70b-versatile` (default)
- `mixtral-8x7b-32768`
- `gemma-7b-it`

## 🔧 Troubleshooting

### Issue: "USER_PASSWORD_AUTH flow not enabled"

**Solution:**
1. Go to AWS Cognito Console
2. Select your User Pool
3. Navigate to **App integration** → **App clients**
4. Click on your app client
5. Click **Edit**
6. Under **Authentication flows**, enable:
   - ✅ ALLOW_USER_PASSWORD_AUTH
7. Save changes

### Issue: "Unable to locate credentials"

**Solution:**
- Ensure AWS credentials are configured (if running locally)
- Or ensure EC2 instance has appropriate IAM role (if deployed)
- Or add AWS credentials to `.env`:
  ```
  AWS_ACCESS_KEY_ID=your_key
  AWS_SECRET_ACCESS_KEY=your_secret
  ```

### Issue: Application not starting

**Solution:**
```bash
# Reinstall dependencies
pip install -r requirements.txt --upgrade

# Check Python version
python --version  # Should be 3.9+

# Run with verbose logging
streamlit run app/app.py --logger.level=debug
```

## 📦 Dependencies

- **streamlit** - Web application framework
- **langchain** - LLM orchestration
- **langchain-groq** - Groq integration
- **boto3** - AWS SDK for Cognito
- **chromadb** - Vector database
- **pandas** - Data processing
- **unstructured** - Document parsing

## 🏗️ Project Structure

```
Email-Generator/
├── app/
│   ├── .env                    # Environment variables
│   ├── app.py                  # Main app with authentication
│   ├── main.py                 # App without authentication
│   ├── auth.py                 # Authentication module
│   ├── chains.py               # LangChain logic
│   ├── portfolio.py            # Portfolio management
│   ├── utils.py                # Utility functions
│   └── resource/
│       └── my_portfolio.csv    # Portfolio data
├── vectorstore/                # Chroma DB storage
├── imgs/                       # Application images
├── requirements.txt            # Python dependencies
└── README.md                   # Documentation
```

## 🔒 Security Best Practices

1. **Never commit `.env` files** - Already in `.gitignore`
2. **Use strong passwords** - Min 8 characters with uppercase, lowercase, and numbers
3. **Enable MFA** - Optional but recommended in Cognito
4. **Rotate API keys** - Regularly update Groq and AWS credentials
5. **Use HTTPS** - In production deployments

## 🚀 Deployment

### Deploy to AWS EC2:

1. Launch EC2 instance (Ubuntu 22.04)
2. Install dependencies:
   ```bash
   sudo apt update
   sudo apt install python3-pip
   pip3 install -r requirements.txt
   ```
3. Configure IAM role with Cognito permissions
4. Run application:
   ```bash
   streamlit run app/app.py --server.port 8501 --server.address 0.0.0.0
   ```

### Deploy with Docker:

```dockerfile
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 8501
CMD ["streamlit", "run", "app/app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

## 📄 License

Copyright (C) Codebasics Inc. All rights reserved.

**Additional Terms:**
This software is licensed under the MIT License. However, commercial use of this software is strictly prohibited without prior written permission from the author. Attribution must be given in all copies or substantial portions of the software.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Support

For issues and questions, please open an issue on GitHub.

---

**Made with ❤️ using Groq, LangChain, and Streamlit**
