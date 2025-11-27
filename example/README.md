# SimpleWebAuthn Example - Passkey Authentication Demo

A complete WebAuthn/Passkey authentication demo deployed on Vercel. This example demonstrates passwordless authentication using passkeys with support for Windows Hello, iCloud Keychain, Google Password Manager, Bitwarden, and more.

🔗 **Live Demo:** [https://example-seven-weld.vercel.app](https://example-seven-weld.vercel.app)

---

## 📋 Table of Contents

- [Features](#-features)
- [Prerequisites](#-prerequisites)
- [Local Development Setup](#-local-development-setup)
- [Vercel Deployment](#-vercel-deployment)
- [How to Use the App](#-how-to-use-the-app)
- [API Endpoints](#-api-endpoints)
- [Understanding Passkeys](#-understanding-passkeys)
- [Credential Sources](#-credential-sources)
- [Troubleshooting](#-troubleshooting)

---

## ✨ Features

- **Passwordless Authentication** - Sign in with just a passkey, no password needed
- **Multi-Device Support** - Register passkeys from Windows, macOS, iOS, Android
- **Multiple Authenticators** - Supports Windows Hello, Face ID, Touch ID, Bitwarden, 1Password, Google Password Manager
- **Credential Tracking** - See detailed info about each registered passkey
- **Device Detection** - Automatically detects browser, OS, and authenticator type

---

## 📦 Prerequisites

- [Node.js](https://nodejs.org/) v18 or higher
- [Vercel CLI](https://vercel.com/cli) - `npm install -g vercel`
- A [Vercel account](https://vercel.com/signup) (free tier works)
- A browser that supports WebAuthn (Chrome, Edge, Safari, Firefox)

---

## 🛠 Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/Obad94/SimpleWebAuthn.git
cd SimpleWebAuthn/example
```

### 2. Install Dependencies

```bash
npm install
```

### 3. Run Locally

```bash
npm start
```

The server will start at `http://localhost:8000`

> ⚠️ **Note:** WebAuthn requires HTTPS in production. For local development, use `localhost` which is treated as a secure context.

---

## 🚀 Vercel Deployment

### Step 1: Install Vercel CLI

```bash
npm install -g vercel
```

### Step 2: Login to Vercel

```bash
vercel login
```

This will open a browser window to authenticate with your Vercel account.

### Step 3: Deploy the Example

Navigate to the example folder and deploy:

```bash
cd SimpleWebAuthn/example
vercel
```

Follow the prompts:
- **Set up and deploy?** Yes
- **Which scope?** Select your account
- **Link to existing project?** No (first time) / Yes (subsequent deploys)
- **Project name?** `example` (or your preferred name)
- **Directory?** `./` (current directory)

### Step 4: Configure Environment Variables

In the Vercel dashboard or via CLI, set:

```bash
vercel env add RP_ID
# Enter: your-project-name.vercel.app (e.g., example-seven-weld.vercel.app)
```

### Step 5: Deploy to Production

```bash
vercel --prod
```

Your app is now live! 🎉

### Step 6: Set Up Custom Domain (Optional)

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Select your project
3. Go to **Settings** → **Domains**
4. Add your custom domain
5. Update `RP_ID` environment variable to match

---

## 📱 How to Use the App

### User Interface Overview

```
┌─────────────────────────────────────────────────────────────┐
│        SimpleWebAuthn Example Site                          │
├─────────────────────────────────────────────────────────────┤
│  Username (Email)  [_________________________]              │
│  Password          [_________________________]              │
├─────────────────────────────────────────────────────────────┤
│  New User?                                                  │
│  [🚪 Register New Account]                                  │
│  Creates account + first passkey                            │
├─────────────────────────────────────────────────────────────┤
│  Add Another Passkey?                                       │
│  [➕ Add Passkey to Account]                                │
│  Login first, then add new device/passkey                   │
├─────────────────────────────────────────────────────────────┤
│  Existing User?                                             │
│  [🔑 Sign In with Passkey]                                  │
│  No password needed - just use your passkey!                │
│                                                             │
│  [📧 Sign In with Email + Password]                         │
│  Traditional login (if no passkey available)                │
└─────────────────────────────────────────────────────────────┘
```

### User Flows

#### 1. Register a New Account
1. Enter your **email** and **password**
2. Click **"🚪 Register New Account"**
3. Choose where to save your passkey:
   - Windows Hello (Windows)
   - Touch ID / Face ID (Mac/iPhone/iPad)
   - Google Password Manager (Chrome/Android)
   - Bitwarden, 1Password, etc.
4. ✅ Account created with your first passkey!

#### 2. Add Another Passkey (Different Device)
1. Enter your **email** and **password**
2. Click **"➕ Add Passkey to Account"**
3. Save the passkey to your current device's authenticator
4. ✅ Now you can sign in from multiple devices!

#### 3. Sign In with Passkey (Passwordless!)
1. Click **"🔑 Sign In with Passkey"** - no email/password needed!
2. Browser shows all your passkeys for this site
3. Select your passkey and authenticate
4. ✅ You're logged in!

#### 4. Sign In with Email + Password (Traditional)
1. Enter your **email** and **password**
2. Click **"📧 Sign In with Email + Password"**
3. ✅ You're logged in the traditional way

---

## 🔌 API Endpoints

### Public Pages

| URL | Description |
|-----|-------------|
| [/](https://example-seven-weld.vercel.app/) | Main application UI |
| [/list-credentials](https://example-seven-weld.vercel.app/list-credentials) | View all registered passkeys for logged-in user |

### Authentication Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/register-user` | Create a new user account |
| `POST` | `/login` | Traditional email/password login |
| `GET` | `/generate-registration-options` | Get WebAuthn registration options |
| `POST` | `/verify-registration` | Verify and save a new passkey |
| `GET` | `/generate-authentication-options` | Get WebAuthn auth options (requires login) |
| `POST` | `/verify-authentication` | Verify passkey authentication |
| `GET` | `/generate-passwordless-options` | Get passwordless auth options |
| `POST` | `/verify-passwordless` | Verify passwordless authentication |
| `GET` | `/list-credentials` | List all passkeys for current user |

### Example: List Credentials

After logging in, visit:
```
https://example-seven-weld.vercel.app/list-credentials
```

Response:
```json
{
  "user": {
    "id": "user_1234567890",
    "username": "user@example.com"
  },
  "totalCredentials": 4,
  "credentials": [
    {
      "index": 1,
      "id": "abc123...",
      "credentialSource": "Synced Passkey (Phone/Cloud)",
      "deviceType": "multiDevice",
      "backedUp": true,
      "browser": "Chrome 142",
      "os": "Windows 10/11",
      "device": "Desktop",
      "authenticatorType": "platform",
      "transports": ["hybrid", "internal"],
      "registeredAt": "2025-11-27T15:13:56.970Z"
    },
    {
      "index": 2,
      "id": "def456...",
      "credentialSource": "Google Password Manager",
      "deviceType": "multiDevice",
      "backedUp": true,
      "browser": "Chrome 142",
      "os": "Android 10",
      "device": "Android Phone",
      "authenticatorType": "platform",
      "transports": ["hybrid", "internal"],
      "registeredAt": "2025-11-27T15:15:54.160Z"
    },
    {
      "index": 3,
      "id": "ghi789...",
      "credentialSource": "Windows Hello",
      "deviceType": "singleDevice",
      "backedUp": false,
      "browser": "Chrome 142",
      "os": "Windows 10/11",
      "device": "Desktop",
      "authenticatorType": "platform",
      "transports": ["internal"],
      "registeredAt": "2025-11-27T15:17:02.509Z"
    },
    {
      "index": 4,
      "id": "jkl012...",
      "credentialSource": "iCloud Keychain",
      "deviceType": "multiDevice",
      "backedUp": true,
      "browser": "Safari 18",
      "os": "macOS",
      "device": "Desktop",
      "authenticatorType": "platform",
      "transports": ["internal", "hybrid"],
      "registeredAt": "2025-11-27T15:22:11.468Z"
    }
  ]
}
```

---

## 🔐 Understanding Passkeys

### What is a Passkey?

A passkey is a cryptographic credential that replaces passwords. It consists of:
- **Private Key** - Stored securely on your device/authenticator
- **Public Key** - Stored on the server

### How Passkeys Work

```
┌──────────────────┐                    ┌──────────────────┐
│   Your Device    │                    │     Server       │
│                  │                    │                  │
│  ┌────────────┐  │   Registration     │  ┌────────────┐  │
│  │ Private Key│  │ ───────────────►   │  │ Public Key │  │
│  │  (secret)  │  │   Sends public     │  │  (stored)  │  │
│  └────────────┘  │      key           │  └────────────┘  │
│                  │                    │                  │
│  ┌────────────┐  │   Authentication   │  ┌────────────┐  │
│  │  Sign with │  │ ◄───────────────   │  │  Verify    │  │
│  │ Private Key│  │   Challenge        │  │ Signature  │  │
│  └────────────┘  │ ───────────────►   │  └────────────┘  │
│                  │   Signed response  │                  │
└──────────────────┘                    └──────────────────┘
```

### Device Types

| Type | Description | Example |
|------|-------------|---------|
| `singleDevice` | Passkey is bound to one device only | Windows Hello |
| `multiDevice` | Passkey syncs across devices | iCloud Keychain, Google Password Manager |

### Backup Status

| Status | Meaning |
|--------|---------|
| `backedUp: true` | Passkey is synced to cloud, recoverable if device is lost |
| `backedUp: false` | Passkey only exists on this device, lost if device is lost |

---

## 🔍 Credential Sources

The app automatically detects where your passkey is stored:

| OS | Device Type | Backed Up | Detected Source |
|----|-------------|-----------|-----------------|
| Windows | singleDevice | No | Windows Hello |
| Windows | multiDevice | Yes | Cloud Passkey Manager (Chrome/Bitwarden) |
| macOS | multiDevice | Yes | iCloud Keychain |
| iOS/iPadOS | multiDevice | Yes | iCloud Keychain |
| Android | multiDevice | Yes | Google Password Manager |
| Any | multiDevice + hybrid | Yes | Synced Passkey (Phone/Cloud) |

### Recommended Setup for Cross-Device Access

To access your account from any device, register passkeys using:

1. **iCloud Keychain** (Apple devices) - Works on Mac, iPhone, iPad
2. **Google Password Manager** (Chrome/Android) - Works anywhere you're signed into Chrome
3. **Bitwarden/1Password** - Works on all platforms where the app is installed

---

## 🔧 Troubleshooting

### "Bluetooth is off" prompt during authentication

**Cause:** Chrome detected a credential with `hybrid` transport and is trying cross-device auth.

**Solution:** The code has been updated to not restrict transports. If you still see this, the passkey was originally saved with hybrid transport. Register a new passkey.

### Passkey not showing during authentication

**Causes:**
1. Passkey was saved on a different device
2. Browser doesn't recognize the credential source

**Solution:** 
- Use "Sign In with Passkey" which shows all discoverable credentials
- Or use "Add Passkey to Account" to register a new passkey on this device

### "User already exists" error

**Cause:** Trying to register a new account with an email that's already registered.

**Solution:** Use "Add Passkey to Account" instead to add a new passkey to your existing account.

### Passkeys not syncing across devices

**Cause:** Using Windows Hello (singleDevice) instead of a cloud-based authenticator.

**Solution:** Register a new passkey using:
- Google Password Manager (Chrome)
- iCloud Keychain (Safari/Apple devices)
- Bitwarden or 1Password

### "Authenticator is not registered with this site" error

**Cause:** The passkey you're trying to use wasn't registered for this account.

**Solution:** 
- Make sure you're using the correct passkey
- Check `/list-credentials` to see which passkeys are registered
- Add a new passkey if needed

---

## 📁 Project Structure

```
example/
├── api/
│   └── index.ts          # Vercel serverless function entry
├── public/
│   ├── index.html        # Main UI
│   └── styles.css        # Styling
├── index.ts              # Express server with all routes
├── example-server.d.ts   # TypeScript type definitions
├── package.json          # Dependencies
├── tsconfig.json         # TypeScript config
├── vercel.json           # Vercel configuration
└── README.md             # This file
```

---

## 🔄 Redeploying Updates

After making changes:

```bash
# Commit changes
git add -A
git commit -m "Your commit message"
git push origin master

# Deploy to Vercel
cd example
vercel --prod
```

---

## 📊 Server Logs on Vercel

To view logs:

1. Go to [Vercel Dashboard](https://vercel.com/dashboard)
2. Select your project
3. Click **Logs** tab
4. Filter by function: `/api`

Example log entries:
```
👤 New user registered: { userId: 'user_123', username: 'user@example.com' }
🔐 New credential registered: { credentialId: 'abc123', credentialSource: 'Windows Hello' }
🔑 Passwordless authentication requested
✅ Passwordless authentication successful: { username: 'user@example.com' }
```

---

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE.md](../LICENSE.md) file for details.

---

## 🔗 Resources

- [SimpleWebAuthn Documentation](https://simplewebauthn.dev/docs/)
- [WebAuthn Guide](https://webauthn.guide/)
- [Passkeys.dev](https://passkeys.dev/)
- [FIDO Alliance](https://fidoalliance.org/)

---

## 📞 Support

- **Issues:** [GitHub Issues](https://github.com/Obad94/SimpleWebAuthn/issues)
- **SimpleWebAuthn Docs:** [simplewebauthn.dev](https://simplewebauthn.dev/)
