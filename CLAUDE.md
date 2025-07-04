# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

- **Development**: `npm run dev` - Start development server with hot reload using tsx
- **Build**: `npm run build` - Compile TypeScript to JavaScript in dist/ directory
- **Start**: `npm run start` - Run the built application from dist/index.js
- **Install**: `npm install` - Install dependencies

## Architecture

This is a Node.js TypeScript server using the Hono web framework for building a passkey authentication demo. The project structure is minimal and focused:

- **Framework**: Hono.js with @hono/node-server adapter
- **Language**: TypeScript with ES modules (type: "module")
- **Entry Point**: `src/index.ts` - Main server file with basic Hono app setup
- **Build Output**: `dist/` directory for compiled JavaScript
- **Dependencies**: @simplewebauthn/server for WebAuthn/passkey functionality

The server runs on port 3000 by default. The codebase is currently in early stages with basic Hono setup and @simplewebauthn/server dependency suggesting future passkey implementation.

## Development Notes

- Uses tsx for development with watch mode
- TypeScript configured with strict mode and NodeNext module resolution
- JSX support configured for Hono's JSX implementation
- No test framework currently configured