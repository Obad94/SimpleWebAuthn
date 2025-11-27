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
      transports: cred.transports,
    })),
    authenticatorSelection: {
      residentKey: 'discouraged',
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
      const newCredential: WebAuthnCredential = {
        id: credential.id,
        publicKey: credential.publicKey,
        counter: credential.counter,
        transports: body.response.transports,
        // Store device-identifying information
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        // You can also store custom metadata from the request
        userAgent: req.headers['user-agent'],
        registeredAt: new Date().toISOString(),
      };
      user.credentials.push(newCredential);

      console.log('🔐 New credential registered:', {
        userId: user.id,
        username: user.username,
        credentialId: credential.id,
        deviceType: credentialDeviceType,
        backedUp: credentialBackedUp,
        userAgent: req.headers['user-agent'],
        registeredAt: new Date().toISOString(),
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

  console.log('🔑 Authentication requested:', {
    userId: user.id,
    username: user.username,
    registeredCredentials: user.credentials.length,
    userAgent: req.headers['user-agent'],
  });

  const opts: GenerateAuthenticationOptionsOpts = {
    timeout: 60000,
    allowCredentials: user.credentials.map((cred) => ({
      id: cred.id,
      type: 'public-key',
      transports: cred.transports,
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

    console.log('✅ Authentication successful:', {
      userId: user.id,
      username: user.username,
      credentialId: dbCredential.id,
      credentialDeviceType: dbCredential.deviceType,
      credentialBackedUp: dbCredential.backedUp,
      credentialRegisteredAt: dbCredential.registeredAt,
      credentialUserAgent: dbCredential.userAgent,
      currentUserAgent: req.headers['user-agent'],
      counterUpdated: `${authenticationInfo.newCounter}`,
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
