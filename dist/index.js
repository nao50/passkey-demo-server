import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { logger } from 'hono/logger';
import { sign, verify } from 'hono/jwt';
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse, } from '@simplewebauthn/server';
const app = new Hono();
app.use('*', logger());
app.use('*', cors({
    origin: '*',
    allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    // allowHeaders: ['Content-Type', 'Authorization'],
    // credentials: true
}));
// In-memory storage for demo purposes
const users = new Map();
const challenges = new Map();
// Configuration
const rpName = 'Passkey Demo';
const rpID = 'localhost';
const JWT_SECRET = 'demo-secret-key-please-change-in-production';
// Mock data for JWT payload
const mockPayload = {
    iccid: "8942310xxxxxxxxxxxx",
    otaSupported: true,
    primaryImsi: "29505xxxxxxxxx",
    subscribers: {
        "29505xxxxxxxxx": {
            capabilities: {
                data: true,
                sms: true,
                voice: true,
            },
            imsi: "29505xxxxxxxxxxxx",
            msisdn: "xxxxxxxxxxxx",
            status: "active",
            subscription: "plan01s"
        },
        "441200xxxxxxxxx": {
            capabilities: {
                data: true,
                sms: false,
                voice: false,
            },
            imsi: "441200xxxxxxxxx",
            msisdn: "8120xxxxxxxxxxx",
            status: "active",
            subscription: "planX2"
        }
    }
};
app.get('/', (c) => {
    return c.text('Passkey Demo Server');
});
// Registration endpoints
app.post('/attestation/option', async (c) => {
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
            // residentKey: 'preferred',
            // userVerification: 'preferred',
            requireResidentKey: false,
            userVerification: 'discouraged',
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
        expectedOrigin: 'http://localhost:4200',
        expectedRPID: rpID,
        requireUserVerification: false,
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
app.post('/assertion/option', async (c) => {
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
        // expectedOrigin: origin,
        expectedOrigin: 'http://localhost:4200',
        expectedRPID: rpID,
        credential: {
            id: userCredential.id,
            publicKey: userCredential.publicKey,
            counter: userCredential.counter,
        },
        requireUserVerification: false,
    };
    try {
        const verification = await verifyAuthenticationResponse(opts);
        if (verification.verified) {
            userCredential.counter = verification.authenticationInfo.newCounter;
            // Generate JWT token
            const token = await sign({
                ...mockPayload,
                sub: username,
                iat: Math.floor(Date.now() / 1000),
                exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), // 24 hours
            }, JWT_SECRET);
            return c.json({
                verified: true,
                accessToken: token
            });
        }
        return c.json({ verified: false, error: 'Authentication failed' }, 400);
    }
    catch (error) {
        return c.json({ verified: false, error: error.message }, 400);
    }
});
// JWT verification endpoint
app.get('/verify', async (c) => {
    const authHeader = c.req.header('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return c.json({ status: 'NG', error: 'Authorization header required' }, 401);
    }
    const token = authHeader.substring(7); // Remove 'Bearer ' prefix
    try {
        const decoded = await verify(token, JWT_SECRET);
        // Log ICCID and IMSI list to console
        console.log('=== JWT Verification Success ===');
        console.log('ICCID:', decoded.iccid);
        console.log('Primary IMSI:', decoded.primaryImsi);
        console.log('Subscriber IMSIs:');
        Object.entries(decoded.subscribers).forEach(([_, subscriber]) => {
            console.log(`  - ${subscriber.imsi} (${subscriber.status})`);
        });
        console.log('================================');
        return c.json({ status: 'OK' });
    }
    catch (error) {
        console.log('JWT verification failed:', error.message);
        return c.json({ status: 'NG', error: 'Invalid token' }, 401);
    }
});
serve({
    fetch: app.fetch,
    port: 3000
}, (info) => {
    console.log(`Server is running on http://localhost:${info.port}`);
});
