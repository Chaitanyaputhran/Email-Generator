# 📄 Resume Upload Feature Guide

## Overview

The Email Generator now supports **user resume uploads** with secure storage in AWS S3. This feature personalizes cold emails based on your actual skills, experience, and projects instead of a generic portfolio CSV file.

---

## 🎯 Key Features

### 1. **Resume-Based Email Personalization**
- Upload your resume (PDF, DOCX, DOC, or TXT format)
- AI extracts your skills, experience, and projects
- Generated emails are tailored to YOUR profile
- Better job matching based on your actual qualifications

### 2. **Secure AWS S3 Storage**
- Resumes stored securely in AWS S3
- User-specific storage paths
- Easy update and delete functionality
- Metadata tracking for resume management

### 3. **Intelligent Resume Parsing**
- Extracts technical skills automatically
- Identifies work experience and roles
- Recognizes projects and achievements
- Generates professional summary

### 4. **User-Friendly Interface**
- First-time upload prompt after login
- Sidebar resume management
- Update or delete resume anytime
- Skip option available

---

## 🚀 Setup Instructions

### Prerequisites

1. **AWS Account** with S3 access
2. **Existing AWS Cognito Configuration** (already set up)
3. **Python 3.9+** installed

### Step 1: Configure AWS S3 Bucket

#### Option A: Create S3 Bucket via AWS Console

1. Go to **AWS Console** → **S3**
2. Click **Create bucket**
3. Bucket name: `email-generator-resumes` (or your preferred name)
4. Region: Choose same region as Cognito (e.g., `eu-north-1`)
5. **Block Public Access**: Keep all public access blocked (recommended)
6. Click **Create bucket**

#### Option B: Create S3 Bucket via AWS CLI

```bash
aws s3 mb s3://email-generator-resumes --region eu-north-1
```

### Step 2: Configure IAM Permissions

The IAM user/role needs S3 permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:GetObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:HeadBucket"
      ],
      "Resource": [
        "arn:aws:s3:::email-generator-resumes",
        "arn:aws:s3:::email-generator-resumes/*"
      ]
    }
  ]
}
```

### Step 3: Update Environment Variables

The `.env` file already contains the S3 bucket configuration:

```bash
# AWS S3 Configuration for Resume Storage
S3_BUCKET_NAME=email-generator-resumes
```

**Note**: Change `email-generator-resumes` to your actual bucket name if different.

### Step 4: Install New Dependencies

```bash
pip install -r requirements.txt
```

New dependencies added:
- `pypdf==4.0.1` - For PDF resume parsing
- `python-docx==1.1.0` - For DOCX resume parsing

---

## 📖 How to Use

### For First-Time Users

1. **Login** to your account
2. You'll be prompted to **upload your resume**
3. Click **"Choose your resume file"**
4. Select resume (PDF, DOCX, DOC, or TXT)
5. Click **"📤 Upload Resume"**
6. Wait for confirmation
7. Start generating personalized emails!

**Optional**: Click **"⏭️ Skip for Now"** to upload later

### Managing Your Resume

Access resume management from the **sidebar**:

#### ✅ If Resume Uploaded
- **Status**: "✅ Resume uploaded"
- **🔄 Update**: Upload a new version
- **🗑️ Delete**: Remove current resume

#### ⚠️ If No Resume
- **Status**: "⚠️ No resume uploaded"
- **📤 Upload Resume**: Add your resume

### Generating Personalized Emails

1. Enter a **job posting URL**
2. Click **"🚀 Generate Email"**
3. System extracts job requirements
4. Matches YOUR skills from resume
5. Generates personalized cold email
6. Copy and customize!

---

## 🏗️ Architecture

### Data Flow

```
User Login
    ↓
Resume Upload (Optional)
    ↓
S3 Storage (resumes/{username}/timestamp_filename.pdf)
    ↓
AI Parsing (Extract skills, experience, projects)
    ↓
Vector Database (ChromaDB - user-specific collection)
    ↓
Job Posting Analysis
    ↓
Skill Matching
    ↓
Personalized Email Generation
```

### File Structure

```
Email-Generator/
├── app/
│   ├── s3_manager.py          # S3 upload/download/management
│   ├── resume_parser.py       # Resume parsing and extraction
│   ├── portfolio.py           # Updated to use resumes
│   ├── chains.py              # Updated email generation
│   ├── app.py                 # UI with resume upload
│   └── .env                   # S3 configuration
├── requirements.txt           # Updated dependencies
└── RESUME_FEATURE_GUIDE.md   # This file
```

### S3 Bucket Structure

```
email-generator-resumes/
├── resumes/
│   ├── user1/
│   │   ├── 20241126_120000_resume.pdf
│   │   └── 20241127_150000_updated_resume.pdf
│   └── user2/
│       └── 20241126_140000_cv.docx
└── metadata/
    ├── user1/
    │   └── resume_metadata.json
    └── user2/
        └── resume_metadata.json
```

---

## 🔧 Technical Details

### Resume Parser

**Supported Formats**:
- PDF (`.pdf`)
- Microsoft Word (`.docx`, `.doc`)
- Plain Text (`.txt`)

**Extracted Information**:
- Technical skills (languages, frameworks, tools)
- Work experience (companies, roles, duration)
- Education qualifications
- Projects and achievements
- Professional summary

### S3 Manager

**Key Methods**:
- `upload_resume()` - Upload user resume
- `download_resume()` - Retrieve resume
- `check_user_has_resume()` - Check upload status
- `delete_resume()` - Remove resume
- `list_user_resumes()` - List all versions

### Portfolio System

**Resume-First Approach**:
1. Checks for user resume in S3
2. Parses resume if available
3. Falls back to CSV portfolio if no resume
4. Creates user-specific vector collection

### Email Generation

**Personalization**:
- Uses actual skills from YOUR resume
- References YOUR experience
- Mentions YOUR projects
- Tailored to YOUR profile

---

## 🔒 Security & Privacy

### Data Security
- ✅ Resumes stored in private S3 bucket
- ✅ No public access to resume files
- ✅ User-specific file paths
- ✅ Secure AWS IAM permissions

### Privacy
- ✅ Only YOU can access your resume
- ✅ Resumes never shared between users
- ✅ Delete anytime from sidebar
- ✅ No resume data in application logs

---

## 🐛 Troubleshooting

### Issue: "S3 bucket not configured"

**Solution**: Check `.env` file has `S3_BUCKET_NAME` set correctly.

### Issue: "Access Denied" when uploading

**Solution**: 
1. Verify IAM user has S3 permissions
2. Check bucket name is correct
3. Ensure bucket exists in AWS

### Issue: "Failed to parse resume"

**Solution**:
1. Verify file format (PDF, DOCX, DOC, TXT only)
2. Check file isn't corrupted
3. Ensure file size is reasonable (< 10MB recommended)
4. Try different format (e.g., PDF if DOCX fails)

### Issue: Resume parsing extracts few skills

**Solution**:
1. Ensure resume has clear skill sections
2. Use standard resume format
3. List skills explicitly
4. Update resume with more keywords

### Issue: "No resume found" after upload

**Solution**:
1. Wait a few seconds and refresh
2. Check S3 bucket in AWS Console
3. Try uploading again
4. Check browser console for errors

---

## 💡 Best Practices

### Resume Format Tips
1. **Clear Structure**: Use standard resume sections
2. **Keywords**: Include specific technical skills
3. **Explicit Skills**: List technologies, languages, frameworks
4. **Experience Details**: Include company names and roles
5. **Projects**: Describe notable projects

### Usage Tips
1. **Upload First**: Best to upload resume before generating emails
2. **Update Regularly**: Keep resume current for best results
3. **Review Generated Emails**: Always review and customize before sending
4. **Multiple Versions**: You can update resume anytime

---

## 🆕 What's New

### Changes from Portfolio CSV

**Before** (CSV-based):
- Generic portfolio links
- Same links for all users
- Manual CSV maintenance
- No personalization

**After** (Resume-based):
- YOUR actual skills and experience
- User-specific profiles
- Automatic extraction
- Highly personalized emails

---

## 📞 Support

### Common Questions

**Q: Can I use both resume and portfolio CSV?**  
A: Yes! The system uses resume first, falls back to CSV if no resume.

**Q: How many resumes can I upload?**  
A: One active resume per user. Updating replaces the previous version.

**Q: Is my resume data secure?**  
A: Yes, stored in private S3 bucket with IAM access controls.

**Q: Can I download my uploaded resume?**  
A: Currently no direct download, but can be added if needed.

**Q: What file size limit for resumes?**  
A: No strict limit, but recommend < 10MB for best performance.

---

## 🎓 Example Workflow

1. **Sign Up** → Create account
2. **Verify Email** → Check inbox
3. **Login** → Enter credentials
4. **Upload Resume** → PDF of your CV
5. **Wait for Parsing** → AI extracts info
6. **Find Job** → Copy job posting URL
7. **Generate Email** → Personalized output
8. **Copy & Send** → Customize and use!

---

## 🔮 Future Enhancements

Potential features for future versions:

- [ ] Multiple resume support (different roles)
- [ ] Resume version history
- [ ] Direct resume download
- [ ] Resume analytics dashboard
- [ ] Cover letter generation
- [ ] Interview prep suggestions
- [ ] Resume optimization tips
- [ ] Skill gap analysis

---

**Made with ❤️ - Now with Resume-Powered Personalization!**
