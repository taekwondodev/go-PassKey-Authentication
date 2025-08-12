# WebAuthn Authentication Client

A simple web client to test the WebAuthn authentication service.

## Prerequisites

- Node.js (v14 or higher)
- A modern browser with WebAuthn support (Chrome 67+, Firefox 60+, Safari 14+, Edge 79+)
- The Go backend service running on port 8080

## Quick Start

1. Install dependencies:
```bash
cd client
npm install
```

2. Start the client server:
```bash
npm start
```

3. Open your browser and navigate to:
```
http://localhost:3000
```

## Features

- **User Registration**: Register new users with WebAuthn credentials
- **User Login**: Authenticate existing users using their passkeys
- **Token Management**: View and refresh JWT access tokens
- **Real-time Logging**: Monitor all authentication activities
- **Backend Connection Status**: Check if the backend service is reachable

## Usage

1. **Registration**:
   - Enter a username (minimum 3 characters)
   - Optionally select a role
   - Click "Start Registration"
   - Follow your browser's prompts to create a passkey

2. **Login**:
   - Enter your username
   - Click "Start Login"
   - Use your passkey to authenticate

3. **Token Management**:
   - View your current access token
   - Refresh tokens when needed
   - Logout to invalidate tokens

## Browser Support

This client requires WebAuthn support. Make sure you're using a compatible browser and that you have a compatible authenticator (built-in biometric sensors, security keys, etc.).