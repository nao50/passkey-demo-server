import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
  type GenerateRegistrationOptionsOpts,
  type VerifyRegistrationResponseOpts,
  type GenerateAuthenticationOptionsOpts,
  type VerifyAuthenticationResponseOpts,
} from '@simplewebauthn/server'

const app = new Hono()

app.use('*', logger())
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  // allowHeaders: ['Content-Type', 'Authorization'],
  // credentials: true
}))

// In-memory storage for demo purposes
const users = new Map<string, {
  id: string
  username: string
  credentials: Array<{
    id: string
    publicKey: Uint8Array
    counter: number
    transports?: any[]
  }>
}>()

const challenges = new Map<string, string>()

// Configuration
const rpName = 'Passkey Demo'
const rpID = 'localhost'
const origin = 'http://localhost:3000'

app.get('/', (c) => {
  return c.text('Passkey Demo Server')
})

// Registration endpoints
app.post('/attestation/option', async (c) => {
  const { username } = await c.req.json()
  
  if (!username) {
    return c.json({ error: 'Username is required' }, 400)
  }

  const user = users.get(username) || {
    id: username,
    username,
    credentials: []
  }

  const opts: GenerateRegistrationOptionsOpts = {
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
  }

  const options = await generateRegistrationOptions(opts)
  challenges.set(username, options.challenge)

  return c.json(options)
})

app.post('/attestation/result', async (c) => {
  const { username, credential } = await c.req.json()
  
  if (!username || !credential) {
    return c.json({ error: 'Username and credential are required' }, 400)
  }

  const expectedChallenge = challenges.get(username)
  if (!expectedChallenge) {
    return c.json({ error: 'Challenge not found' }, 400)
  }

  const opts: VerifyRegistrationResponseOpts = {
    response: credential,
    expectedChallenge,
    expectedOrigin: 'http://localhost:4200',
    expectedRPID: rpID,
    requireUserVerification: false,
  }

  try {
    const verification = await verifyRegistrationResponse(opts)
    
    if (verification.verified && verification.registrationInfo) {
      const { credential: cred } = verification.registrationInfo
      
      let user = users.get(username)
      if (!user) {
        user = {
          id: username,
          username,
          credentials: []
        }
      }
      
      user.credentials.push({
        id: cred.id,
        publicKey: cred.publicKey,
        counter: cred.counter,
        transports: credential.response.transports,
      })
      
      users.set(username, user)
      challenges.delete(username)
      
      return c.json({ verified: true })
    }
    
    return c.json({ verified: false, error: 'Registration failed' }, 400)
  } catch (error) {
    return c.json({ verified: false, error: (error as Error).message }, 400)
  }
})

// Authentication endpoints
app.post('/assertion/option', async (c) => {
  const { username } = await c.req.json()
  
  if (!username) {
    return c.json({ error: 'Username is required' }, 400)
  }

  const user = users.get(username)
  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  const opts: GenerateAuthenticationOptionsOpts = {
    rpID,
    allowCredentials: user.credentials.map(cred => ({
      id: cred.id,
      transports: cred.transports,
    })),
    userVerification: 'preferred',
  }

  const options = await generateAuthenticationOptions(opts)
  challenges.set(username, options.challenge)

  return c.json(options)
})

app.post('/assertion/result', async (c) => {
  const { username, credential } = await c.req.json()
  
  if (!username || !credential) {
    return c.json({ error: 'Username and credential are required' }, 400)
  }

  const user = users.get(username)
  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  const expectedChallenge = challenges.get(username)
  if (!expectedChallenge) {
    return c.json({ error: 'Challenge not found' }, 400)
  }

  const userCredential = user.credentials.find(cred => cred.id === credential.id)
  
  if (!userCredential) {
    return c.json({ error: 'Credential not found' }, 404)
  }

  const opts: VerifyAuthenticationResponseOpts = {
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
  }

  try {
    const verification = await verifyAuthenticationResponse(opts)
    
    if (verification.verified) {
      userCredential.counter = verification.authenticationInfo.newCounter
      return c.json({ verified: true })
    }
    
    return c.json({ verified: false, error: 'Authentication failed' }, 400)
  } catch (error) {
    return c.json({ verified: false, error: (error as Error).message }, 400)
  }
})

serve({
  fetch: app.fetch,
  port: 3000
}, (info) => {
  console.log(`Server is running on http://localhost:${info.port}`)
})
