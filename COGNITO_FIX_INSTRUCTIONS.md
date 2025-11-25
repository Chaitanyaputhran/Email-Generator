# Fix: USER_PASSWORD_AUTH Flow Not Enabled

## Error Message:
```
USER_PASSWORD_AUTH flow not enabled for this client
```

## Solution: Enable USER_PASSWORD_AUTH in AWS Cognito

### Quick Steps (5 minutes):

1. **Go to AWS Cognito Console:**
   - Open AWS Console
   - Search for "Cognito"
   - Click "User pools"

2. **Select Your User Pool:**
   - Click on User Pool: `eu-north-1_q7RFSJF7j`

3. **Find Your App Client:**
   - Click on **"App integration"** tab
   - Scroll to **"App clients and analytics"** section
   - Find app client with ID: `71sqc58ic5u1ft2c57lv71hgue`
   - Click on the app client name

4. **Enable Authentication Flow:**
   - Click **"Edit"** or **"Edit authentication flows"** button
   - Under **"Authentication flows"**, enable these checkboxes:
     - ✅ **ALLOW_USER_PASSWORD_AUTH** ← **CRITICAL**
     - ✅ **ALLOW_REFRESH_TOKEN_AUTH** (recommended)
     - ✅ **ALLOW_USER_SRP_AUTH** (optional)
   - Click **"Save changes"**

5. **Test:**
   - Refresh your browser at `http://localhost:8503`
   - Try logging in
   - **Should work now!** ✅

---

## What This Does:

`USER_PASSWORD_AUTH` allows users to authenticate directly with username and password. Without this enabled, Cognito rejects authentication attempts.

---

## Alternative (If you can't change Cognito settings):

I can update the code to use `USER_SRP_AUTH` flow instead, which is more secure but slightly more complex. Let me know if you need this option.

---

## Verification:

After enabling, you should be able to:
- ✅ Login with username and password
- ✅ Login with email and password
- ✅ All authentication features working

**Once enabled, no code changes or app restart needed - just refresh the browser!**
