import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse, } from '@simplewebauthn/server';
const app = new Hono();
app.use('*', cors());
// In-memory storage for demo purposes
const users = new Map();
const challenges = new Map();
// Configuration
const rpName = 'Passkey Demo';
const rpID = 'localhost';
const origin = 'http://localhost:3000';
app.get('/', (c) => {
    return c.text('Passkey Demo Server');
});
// Registration endpoints
app.post('/attestation/options', async (c) => {
    const { username } = await c.req.json();
    if (!username) {
        return c.json({ error: 'Username is required' }, 400);
    }
    const user = users.get(username) || {
        id: username,
        username,
        credentials: []
    };
    const opts = {
        rpName,
        rpID,
        userName: username,
        userID: new TextEncoder().encode(username),
        attestationType: 'none',
        excludeCredentials: user.credentials.map(cred => ({
            id: cred.id,
            transports: cred.transports,
        })),
        authenticatorSelection: {
            residentKey: 'preferred',
            userVerification: 'preferred',
        },
    };
    const options = await generateRegistrationOptions(opts);
    challenges.set(username, options.challenge);
    return c.json(options);
});
app.post('/attestation/result', async (c) => {
    const { username, credential } = await c.req.json();
    if (!username || !credential) {
        return c.json({ error: 'Username and credential are required' }, 400);
    }
    const expectedChallenge = challenges.get(username);
    if (!expectedChallenge) {
        return c.json({ error: 'Challenge not found' }, 400);
    }
    const opts = {
        response: credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
    };
    try {
        const verification = await verifyRegistrationResponse(opts);
        if (verification.verified && verification.registrationInfo) {
            const { credential: cred } = verification.registrationInfo;
            let user = users.get(username);
            if (!user) {
                user = {
                    id: username,
                    username,
                    credentials: []
                };
            }
            user.credentials.push({
                id: cred.id,
                publicKey: cred.publicKey,
                counter: cred.counter,
                transports: credential.response.transports,
            });
            users.set(username, user);
            challenges.delete(username);
            return c.json({ verified: true });
        }
        return c.json({ verified: false, error: 'Registration failed' }, 400);
    }
    catch (error) {
        return c.json({ verified: false, error: error.message }, 400);
    }
});
// Authentication endpoints
app.post('/assertion/options', async (c) => {
    const { username } = await c.req.json();
    if (!username) {
        return c.json({ error: 'Username is required' }, 400);
    }
    const user = users.get(username);
    if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }
    const opts = {
        rpID,
        allowCredentials: user.credentials.map(cred => ({
            id: cred.id,
            transports: cred.transports,
        })),
        userVerification: 'preferred',
    };
    const options = await generateAuthenticationOptions(opts);
    challenges.set(username, options.challenge);
    return c.json(options);
});
app.post('/assertion/result', async (c) => {
    const { username, credential } = await c.req.json();
    if (!username || !credential) {
        return c.json({ error: 'Username and credential are required' }, 400);
    }
    const user = users.get(username);
    if (!user) {
        return c.json({ error: 'User not found' }, 404);
    }
    const expectedChallenge = challenges.get(username);
    if (!expectedChallenge) {
        return c.json({ error: 'Challenge not found' }, 400);
    }
    const userCredential = user.credentials.find(cred => cred.id === credential.id);
    if (!userCredential) {
        return c.json({ error: 'Credential not found' }, 404);
    }
    const opts = {
        response: credential,
        expectedChallenge,
        expectedOrigin: origin,
        expectedRPID: rpID,
        credential: {
            id: userCredential.id,
            publicKey: userCredential.publicKey,
            counter: userCredential.counter,
        },
    };
    try {
        const verification = await verifyAuthenticationResponse(opts);
        if (verification.verified) {
            userCredential.counter = verification.authenticationInfo.newCounter;
            return c.json({ verified: true });
        }
        return c.json({ verified: false, error: 'Authentication failed' }, 400);
    }
    catch (error) {
        return c.json({ verified: false, error: error.message }, 400);
    }
});
serve({
    fetch: app.fetch,
    port: 3000
}, (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
});
