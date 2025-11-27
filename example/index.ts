/**
 * An example Express server showing off a simple integration of @simplewebauthn/server.
 *
 * The webpages served from ./public use @simplewebauthn/browser.
 */

import https from 'https';
import http from 'http';
import fs from 'fs';

import express from 'express';
import session from 'express-session';
import memoryStore from 'memorystore';
import dotenv from 'dotenv';

dotenv.config();

import {
  AuthenticationResponseJSON,
  // Authentication
  generateAuthenticationOptions,
  GenerateAuthenticationOptionsOpts,
  // Registration
  generateRegistrationOptions,
  GenerateRegistrationOptionsOpts,
  RegistrationResponseJSON,
  VerifiedAuthenticationResponse,
  VerifiedRegistrationResponse,
  verifyAuthenticationResponse,
  VerifyAuthenticationResponseOpts,
  verifyRegistrationResponse,
  VerifyRegistrationResponseOpts,
} from '@simplewebauthn/server';

import { LoggedInUser, WebAuthnCredential } from './example-server';

const app = express();
const MemoryStore = memoryStore(session);

const {
  ENABLE_CONFORMANCE,
  ENABLE_HTTPS,
  RP_ID = 'localhost',
  VERCEL,
} = process.env;

app.use(express.static('./public/'));
app.use(express.json());
app.use(
  session({
    secret: 'secret123',
    saveUninitialized: true,
    resave: false,
    cookie: {
      maxAge: 86400000,
      httpOnly: true, // Ensure to not expose session cookies to clientside scripts
    },
    store: new MemoryStore({
      checkPeriod: 86_400_000, // prune expired entries every 24h
    }),
  }),
);

/**
 * If the words "metadata statements" mean anything to you, you'll want to enable this route. It
 * contains an example of a more complex deployment of SimpleWebAuthn with support enabled for the
 * FIDO Metadata Service. This enables greater control over the types of authenticators that can
 * interact with the Rely Party (a.k.a. "RP", a.k.a. "this server").
 */
if (ENABLE_CONFORMANCE === 'true') {
  import('./fido-conformance').then(
    ({ fidoRouteSuffix, fidoConformanceRouter }) => {
      app.use(fidoRouteSuffix, fidoConformanceRouter);
    },
  );
}

/**
 * RP ID represents the "scope" of websites on which a credential should be usable. The Origin
 * represents the expected URL from which registration or authentication occurs.
 */
export const rpID = RP_ID;
// This value is set at the bottom of page as part of server initialization (the empty string is
// to appease TypeScript until we determine the expected origin based on whether or not HTTPS
// support is enabled)
export let expectedOrigin = '';

/**
 * 2FA and Passwordless WebAuthn flows expect you to be able to uniquely identify the user that
 * performs registration or authentication. The user ID you specify here should be your internal,
 * _unique_ ID for that user (uuid, etc...). Avoid using identifying information here, like email
 * addresses, as it may be stored within the credential.
 *
 * Here, the example server assumes the following user has completed login:
 */
const loggedInUserId = 'internalUserId';

/**
 * Parse User-Agent to extract browser, OS, and device info
 */
function parseUserAgent(userAgent: string | undefined): {
  browser: string;
  browserVersion: string;
  os: string;
  osVersion: string;
  device: string;
} {
  if (!userAgent) {
    return { browser: 'Unknown', browserVersion: '', os: 'Unknown', osVersion: '', device: 'Unknown' };
  }

  let browser = 'Unknown';
  let browserVersion = '';
  let os = 'Unknown';
  let osVersion = '';
  let device = 'Desktop';

  // Detect OS
  if (userAgent.includes('Windows NT 10')) {
    os = 'Windows';
    osVersion = '10/11';
  } else if (userAgent.includes('Windows')) {
    os = 'Windows';
    const match = userAgent.match(/Windows NT (\d+\.\d+)/);
    osVersion = match ? match[1] : '';
  } else if (userAgent.includes('Mac OS X')) {
    os = 'macOS';
    const match = userAgent.match(/Mac OS X (\d+[._]\d+)/);
    osVersion = match ? match[1].replace('_', '.') : '';
  } else if (userAgent.includes('iPhone')) {
    os = 'iOS';
    device = 'iPhone';
    const match = userAgent.match(/iPhone OS (\d+_\d+)/);
    osVersion = match ? match[1].replace('_', '.') : '';
  } else if (userAgent.includes('iPad')) {
    os = 'iPadOS';
    device = 'iPad';
  } else if (userAgent.includes('Android')) {
    os = 'Android';
    device = 'Android Phone';
    const match = userAgent.match(/Android (\d+(\.\d+)?)/);
    osVersion = match ? match[1] : '';
  } else if (userAgent.includes('Linux')) {
    os = 'Linux';
  }

  // Detect Browser
  if (userAgent.includes('Edg/')) {
    browser = 'Edge';
    const match = userAgent.match(/Edg\/(\d+)/);
    browserVersion = match ? match[1] : '';
  } else if (userAgent.includes('Chrome/')) {
    browser = 'Chrome';
    const match = userAgent.match(/Chrome\/(\d+)/);
    browserVersion = match ? match[1] : '';
  } else if (userAgent.includes('Safari/') && !userAgent.includes('Chrome')) {
    browser = 'Safari';
    const match = userAgent.match(/Version\/(\d+)/);
    browserVersion = match ? match[1] : '';
  } else if (userAgent.includes('Firefox/')) {
    browser = 'Firefox';
    const match = userAgent.match(/Firefox\/(\d+)/);
    browserVersion = match ? match[1] : '';
  }

  return { browser, browserVersion, os, osVersion, device };
}

/**
 * Infer credential source based on device type, backup status, OS, and authenticator attachment
 */
function inferCredentialSource(
  deviceType: string,
  backedUp: boolean,
  os: string,
  authenticatorAttachment?: string,
  transports?: string[]
): string {
  // Check transports for hints
  const hasHybrid = transports?.includes('hybrid');
  const hasInternal = transports?.includes('internal');
  
  if (deviceType === 'multiDevice' && backedUp) {
    // Synced passkey
    if (os === 'iOS' || os === 'iPadOS' || os === 'macOS') {
      return 'iCloud Keychain';
    } else if (os === 'Android') {
      return 'Google Password Manager';
    } else if (os === 'Windows') {
      // Could be Google PM, Bitwarden, 1Password, etc.
      if (hasHybrid) {
        return 'Synced Passkey (Phone/Cloud)';
      }
      return 'Cloud Passkey Manager (Chrome/Bitwarden/1Password)';
    }
    return 'Cloud Passkey Manager';
  } else if (deviceType === 'singleDevice') {
    // Device-bound passkey
    if (os === 'Windows') {
      return 'Windows Hello';
    } else if (os === 'macOS') {
      return 'Touch ID (Mac)';
    } else if (os === 'iOS' || os === 'iPadOS') {
      return 'Face ID / Touch ID';
    } else if (os === 'Android') {
      return 'Android Biometric';
    }
    return 'Platform Authenticator';
  }
  
  return 'Unknown Authenticator';
}

const inMemoryUserDB: { [loggedInUserId: string]: LoggedInUser } = {
  [loggedInUserId]: {
    id: loggedInUserId,
    username: `user@${rpID}`,
    credentials: [],
  },
};

/**
 * User Registration and Login with Username/Password
 */
app.post('/register-user', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ error: 'Username and password required' });
  }

  // Check if user already exists
  const existingUser = Object.values(inMemoryUserDB).find(
    (user) => user.username === username
  );

  if (existingUser) {
    return res.status(400).send({ error: 'Username already exists' });
  }

  // Create new user (in production, hash the password!)
  const userId = `user_${Date.now()}`;
  inMemoryUserDB[userId] = {
    id: userId,
    username,
    credentials: [],
  };

  // Log them in
  req.session.userId = userId;

  console.log('👤 New user registered:', {
    userId,
    username,
  });

  res.send({ success: true, userId, username });
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).send({ error: 'Username and password required' });
  }

  // Find user by username
  const user = Object.values(inMemoryUserDB).find(
    (user) => user.username === username
  );

  if (!user) {
    return res.status(401).send({ error: 'Invalid username or password' });
  }

  // In production, verify hashed password here!
  // For this demo, we'll accept any password if user exists

  // Log them in
  req.session.userId = user.id;

  console.log('👤 User logged in:', {
    userId: user.id,
    username: user.username,
  });

  res.send({ success: true, userId: user.id, username: user.username });
});

/**
 * Registration (a.k.a. "Registration")
 */
app.get('/generate-registration-options', async (req, res) => {
  const userId = req.session.userId || loggedInUserId;
  const user = inMemoryUserDB[userId];

  if (!user) {
    return res.status(401).send({ error: 'User not logged in' });
  }

  const {
    /**
     * The username can be a human-readable name, email, etc... as it is intended only for display.
     */
    username,
    credentials,
  } = user;

  const opts: GenerateRegistrationOptionsOpts = {
    rpName: 'SimpleWebAuthn Example',
    rpID,
    userName: username,
    timeout: 60000,
    attestationType: 'none',
    /**
     * Passing in a user's list of already-registered credential IDs here prevents users from
     * registering the same authenticator multiple times. The authenticator will simply throw an
     * error in the browser if it's asked to perform registration when it recognizes one of the
     * credential ID's.
     */
    excludeCredentials: credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      // Don't restrict transports for excludeCredentials
    })),
    authenticatorSelection: {
      // 'preferred' creates discoverable credentials (passkeys) when possible
      // This allows authenticators like Bitwarden, Google Password Manager to store and find them
      residentKey: 'preferred',
      /**
       * Wondering why user verification isn't required? See here:
       *
       * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
       */
      userVerification: 'preferred',
    },
    /**
     * Support the two most common algorithms: ES256, and RS256
     */
    supportedAlgorithmIDs: [-7, -257],
  };

  const options = await generateRegistrationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify the registration response.
   */
  req.session.currentChallenge = options.challenge;

  res.send(options);
});

app.post('/verify-registration', async (req, res) => {
  const body: RegistrationResponseJSON = req.body;

  const userId = req.session.userId || loggedInUserId;
  const user = inMemoryUserDB[userId];

  if (!user) {
    return res.status(401).send({ error: 'User not logged in' });
  }

  const expectedChallenge = req.session.currentChallenge;

  let verification: VerifiedRegistrationResponse;
  try {
    const opts: VerifyRegistrationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: false,
    };
    verification = await verifyRegistrationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, registrationInfo } = verification;

  if (verified && registrationInfo) {
    const { credential, credentialDeviceType, credentialBackedUp } = registrationInfo;

    const existingCredential = user.credentials.find((cred) => cred.id === credential.id);

    if (!existingCredential) {
      /**
       * Add the returned credential to the user's list of credentials
       */
      const userAgentStr = req.headers['user-agent'] as string;
      const parsedUA = parseUserAgent(userAgentStr);
      const credentialSource = inferCredentialSource(
        credentialDeviceType,
        credentialBackedUp,
        parsedUA.os,
        body.authenticatorAttachment,
        body.response.transports
      );

      const newCredential: WebAuthnCredential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: body.response.transports,
        // Store device-identifying information
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        // Enhanced device info
        userAgent: userAgentStr,
        registeredAt: new Date().toISOString(),
        browser: parsedUA.browser,
        browserVersion: parsedUA.browserVersion,
        os: parsedUA.os,
        osVersion: parsedUA.osVersion,
        device: parsedUA.device,
        authenticatorType: body.authenticatorAttachment || 'unknown',
        credentialSource,
      };
      user.credentials.push(newCredential);

      console.log('🔐 New credential registered:', {
        userId: user.id,
        username: user.username,
        credentialId: credential.id,
        credentialSource,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        browser: `${parsedUA.browser} ${parsedUA.browserVersion}`,
        os: `${parsedUA.os} ${parsedUA.osVersion}`,
        device: parsedUA.device,
        authenticatorType: body.authenticatorAttachment,
        transports: body.response.transports,
        registeredAt: newCredential.registeredAt,
      });

      req.session.currentChallenge = undefined;

      // Return full credential info to the client
      return res.send({
        verified,
        credential: {
          id: credential.id,
          credentialSource,
          deviceType: credentialDeviceType,
          backedUp: credentialBackedUp,
          browser: `${parsedUA.browser} ${parsedUA.browserVersion}`,
          os: `${parsedUA.os} ${parsedUA.osVersion}`,
          device: parsedUA.device,
          authenticatorType: body.authenticatorAttachment,
          transports: body.response.transports,
          registeredAt: newCredential.registeredAt,
        },
        user: {
          id: user.id,
          username: user.username,
          totalCredentials: user.credentials.length,
        },
      });
    }
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});

/**
 * Login (a.k.a. "Authentication")
 */
app.get('/generate-authentication-options', async (req, res) => {
  // You need to know the user by this point
  const userId = req.session.userId || loggedInUserId;
  const user = inMemoryUserDB[userId];

  if (!user) {
    return res.status(401).send({ error: 'User not logged in' });
  }

  // Log detailed credential info
  const credentialsSummary = user.credentials.map((cred) => ({
    id: cred.id,
    source: cred.credentialSource || 'Unknown',
    deviceType: cred.deviceType,
    backedUp: cred.backedUp,
    browser: cred.browser,
    os: cred.os,
    registeredAt: cred.registeredAt,
  }));

  console.log('🔑 Authentication requested:', {
    userId: user.id,
    username: user.username,
    registeredCredentials: user.credentials.length,
    credentials: credentialsSummary,
    currentUserAgent: req.headers['user-agent'],
  });

  // For discoverable credentials, we can use empty allowCredentials
  // This lets the authenticator find all passkeys for this RP
  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    // List user's credentials but without transport hints
    // This allows any authenticator (Windows Hello, Bitwarden, Google PM) to respond
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      // Omitting transports lets the browser try ALL authenticators
    })),
    /**
     * Wondering why user verification isn't required? See here:
     *
     * https://passkeys.dev/docs/use-cases/bootstrapping/#a-note-about-user-verification
     */
    userVerification: 'preferred',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  /**
   * The server needs to temporarily remember this value for verification, so don't lose it until
   * after you verify the authentication response.
   */
  req.session.currentChallenge = options.challenge;

  res.send(options);
});

app.post('/verify-authentication', async (req, res) => {
  const body: AuthenticationResponseJSON = req.body;

  const userId = req.session.userId || loggedInUserId;
  const user = inMemoryUserDB[userId];

  if (!user) {
    return res.status(401).send({ error: 'User not logged in' });
  }

  const expectedChallenge = req.session.currentChallenge;

  let dbCredential: WebAuthnCredential | undefined;
  // "Query the DB" here for a credential matching `cred.id`
  for (const cred of user.credentials) {
    if (cred.id === body.id) {
      dbCredential = cred;
      break;
    }
  }

  if (!dbCredential) {
    return res.status(400).send({
      error: 'Authenticator is not registered with this site',
    });
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: dbCredential,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update the credential's counter in the DB to the newest count in the authentication
    dbCredential.counter = authenticationInfo.newCounter;

    // Parse current user agent for comparison
    const currentUA = parseUserAgent(req.headers['user-agent'] as string);

    console.log('✅ Authentication successful:', {
      userId: user.id,
      username: user.username,
      credentialId: dbCredential.id,
      credentialSource: dbCredential.credentialSource,
      credentialDeviceType: dbCredential.deviceType,
      credentialBackedUp: dbCredential.backedUp,
      credentialBrowser: `${dbCredential.browser} ${dbCredential.browserVersion}`,
      credentialOS: `${dbCredential.os} ${dbCredential.osVersion}`,
      credentialRegisteredAt: dbCredential.registeredAt,
      currentBrowser: `${currentUA.browser} ${currentUA.browserVersion}`,
      currentOS: `${currentUA.os} ${currentUA.osVersion}`,
      counterUpdated: `${authenticationInfo.newCounter}`,
    });

    req.session.currentChallenge = undefined;

    // Return full details to the client including all credentials summary
    const allCredentials = user.credentials.map((cred) => ({
      id: cred.id,
      credentialSource: cred.credentialSource || 'Unknown',
      deviceType: cred.deviceType,
      backedUp: cred.backedUp,
      browser: `${cred.browser || 'Unknown'} ${cred.browserVersion || ''}`.trim(),
      os: `${cred.os || 'Unknown'} ${cred.osVersion || ''}`.trim(),
      device: cred.device,
      registeredAt: cred.registeredAt,
      isCurrentCredential: cred.id === dbCredential.id,
    }));

    return res.send({
      verified,
      authenticatedWith: {
        id: dbCredential.id,
        credentialSource: dbCredential.credentialSource,
        deviceType: dbCredential.deviceType,
        backedUp: dbCredential.backedUp,
        browser: `${dbCredential.browser || 'Unknown'} ${dbCredential.browserVersion || ''}`.trim(),
        os: `${dbCredential.os || 'Unknown'} ${dbCredential.osVersion || ''}`.trim(),
        device: dbCredential.device,
        registeredAt: dbCredential.registeredAt,
      },
      currentSession: {
        browser: `${currentUA.browser} ${currentUA.browserVersion}`,
        os: `${currentUA.os} ${currentUA.osVersion}`,
        device: currentUA.device,
      },
      user: {
        id: user.id,
        username: user.username,
        totalCredentials: user.credentials.length,
        allCredentials,
      },
    });
  } else {
    console.log('❌ Authentication failed:', {
      userId: user.id,
      username: user.username,
      credentialId: body.id,
      userAgent: req.headers['user-agent'],
    });
  }

  req.session.currentChallenge = undefined;

  res.send({ verified });
});

/**
 * PASSWORDLESS AUTHENTICATION - No username/password required!
 * Uses discoverable credentials to find the user
 */
app.get('/generate-passwordless-options', async (req, res) => {
  console.log('🔑 Passwordless authentication requested');

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    // Empty allowCredentials = discoverable credentials mode
    // The authenticator will show ALL passkeys for this site
    allowCredentials: [],
    userVerification: 'preferred',
    rpID,
  };

  const options = await generateAuthenticationOptions(opts);

  // Store challenge in session
  req.session.currentChallenge = options.challenge;

  res.send(options);
});

app.post('/verify-passwordless', async (req, res) => {
  const body: AuthenticationResponseJSON = req.body;
  const expectedChallenge = req.session.currentChallenge;

  // With discoverable credentials, we need to find which user owns this credential
  let dbCredential: WebAuthnCredential | undefined;
  let user: LoggedInUser | undefined;

  // Search ALL users for this credential
  for (const [, u] of Object.entries(inMemoryUserDB)) {
    for (const cred of u.credentials) {
      if (cred.id === body.id) {
        dbCredential = cred;
        user = u;
        break;
      }
    }
    if (dbCredential) break;
  }

  if (!dbCredential || !user) {
    return res.status(400).send({
      error: 'Passkey not recognized. Please register first.',
    });
  }

  let verification: VerifiedAuthenticationResponse;
  try {
    const opts: VerifyAuthenticationResponseOpts = {
      response: body,
      expectedChallenge: `${expectedChallenge}`,
      expectedOrigin,
      expectedRPID: rpID,
      credential: dbCredential,
      requireUserVerification: false,
    };
    verification = await verifyAuthenticationResponse(opts);
  } catch (error) {
    const _error = error as Error;
    console.error(_error);
    return res.status(400).send({ error: _error.message });
  }

  const { verified, authenticationInfo } = verification;

  if (verified) {
    // Update counter
    dbCredential.counter = authenticationInfo.newCounter;

    // Log the user in
    req.session.userId = user.id;

    const currentUA = parseUserAgent(req.headers['user-agent'] as string);

    console.log('✅ Passwordless authentication successful:', {
      userId: user.id,
      username: user.username,
      credentialId: dbCredential.id,
      credentialSource: dbCredential.credentialSource,
      currentBrowser: `${currentUA.browser} ${currentUA.browserVersion}`,
      currentOS: `${currentUA.os} ${currentUA.osVersion}`,
    });

    req.session.currentChallenge = undefined;

    // Return user info
    const allCredentials = user.credentials.map((cred) => ({
      id: cred.id,
      credentialSource: cred.credentialSource || 'Unknown',
      deviceType: cred.deviceType,
      backedUp: cred.backedUp,
      browser: `${cred.browser || 'Unknown'} ${cred.browserVersion || ''}`.trim(),
      os: `${cred.os || 'Unknown'} ${cred.osVersion || ''}`.trim(),
      device: cred.device,
      registeredAt: cred.registeredAt,
      isCurrentCredential: cred.id === dbCredential!.id,
    }));

    return res.send({
      verified,
      authenticatedWith: {
        id: dbCredential.id,
        credentialSource: dbCredential.credentialSource,
        deviceType: dbCredential.deviceType,
        browser: `${dbCredential.browser || 'Unknown'} ${dbCredential.browserVersion || ''}`.trim(),
        os: `${dbCredential.os || 'Unknown'} ${dbCredential.osVersion || ''}`.trim(),
      },
      currentSession: {
        browser: `${currentUA.browser} ${currentUA.browserVersion}`,
        os: `${currentUA.os} ${currentUA.osVersion}`,
        device: currentUA.device,
      },
      user: {
        id: user.id,
        username: user.username,
        totalCredentials: user.credentials.length,
        allCredentials,
      },
    });
  }

  req.session.currentChallenge = undefined;
  res.send({ verified });
});

/**
 * List all credentials for the logged-in user
 */
app.get('/list-credentials', (req, res) => {
  const userId = req.session.userId || loggedInUserId;
  const user = inMemoryUserDB[userId];

  if (!user) {
    return res.status(401).send({ error: 'User not logged in' });
  }

  const credentials = user.credentials.map((cred, index) => ({
    index: index + 1,
    id: cred.id,
    credentialSource: cred.credentialSource || 'Unknown',
    deviceType: cred.deviceType,
    backedUp: cred.backedUp,
    browser: `${cred.browser || 'Unknown'} ${cred.browserVersion || ''}`.trim(),
    os: `${cred.os || 'Unknown'} ${cred.osVersion || ''}`.trim(),
    device: cred.device || 'Unknown',
    authenticatorType: cred.authenticatorType,
    transports: cred.transports,
    registeredAt: cred.registeredAt,
  }));

  res.send({
    user: {
      id: user.id,
      username: user.username,
    },
    totalCredentials: credentials.length,
    credentials,
  });
});

// Detect Vercel environment
if (VERCEL) {
  expectedOrigin = `https://${rpID}`;
  console.log(`🚀 Running on Vercel at ${expectedOrigin}`);
} else if (ENABLE_HTTPS) {
  const host = '0.0.0.0';
  const port = 443;
  expectedOrigin = `https://${rpID}`;

  https
    .createServer(
      {
        /**
         * See the README on how to generate this SSL cert and key pair using mkcert
         */
        key: fs.readFileSync(`./${rpID}.key`),
        cert: fs.readFileSync(`./${rpID}.crt`),
      },
      app,
    )
    .listen(port, host, () => {
      console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
    });
} else {
  const host = '0.0.0.0';
  const port = 8000;
  expectedOrigin = `http://${rpID}:${port}`;

  http.createServer(app).listen(port, host, () => {
    console.log(`🚀 Server ready at ${expectedOrigin} (${host}:${port})`);
  });
}

// Export for Vercel serverless
export default app;
