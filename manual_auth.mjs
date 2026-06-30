#!/usr/bin/env node
/**
 * Manual OAuth helper - prints URL, waits for callback code
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import os from 'os';
import readline from 'readline';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const requireBase = os.userInfo().username === 'dmrivers'
    ? path.join(os.homedir(), 'gmail-mcp-server', 'package.json')
    : fileURLToPath(import.meta.url);
const require = createRequire(requireBase);

const { OAuth2Client } = require('google-auth-library');

const CONFIG_DIR = path.join(os.homedir(), '.gmail-mcp');
const OAUTH_PATH = path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
const CREDENTIALS_PATH = path.join(CONFIG_DIR, 'credentials.json');

async function manualAuth() {
    const keys = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
    const k = keys.installed || keys.web;
    const client = new OAuth2Client(k.client_id, k.client_secret, 'http://localhost:3000/oauth2callback');

    const authUrl = client.generateAuthUrl({
        access_type: 'offline',
        scope: [
            'https://www.googleapis.com/auth/gmail.modify',
            'https://www.googleapis.com/auth/gmail.settings.basic',
            'https://www.googleapis.com/auth/calendar.readonly',
        ],
        prompt: 'consent',
    });

    console.log('\n=== MANUAL OAUTH SETUP ===');
    console.log('\n1. Visit this URL in your browser:\n');
    console.log(authUrl);
    console.log('\n2. After authorizing, you\'ll be redirected to localhost:3000/oauth2callback?code=...');
    console.log('3. Copy the ENTIRE URL from your browser address bar and paste it below:\n');

    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    rl.question('Paste the full callback URL here: ', async (answer) => {
        try {
            const url = new URL(answer.trim());
            const code = url.searchParams.get('code');

            if (!code) {
                console.error('Error: No code found in URL');
                process.exit(1);
            }

            console.log('\nExchanging code for tokens...');
            const { tokens } = await client.getToken(code);

            if (!fs.existsSync(CONFIG_DIR)) {
                fs.mkdirSync(CONFIG_DIR, { recursive: true });
            }

            fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens, null, 2));
            console.log('\n✓ Success! Credentials saved to:', CREDENTIALS_PATH);
            console.log('\nYou can now run email_summary.py');

        } catch (err) {
            console.error('Error:', err.message);
            process.exit(1);
        } finally {
            rl.close();
        }
    });
}

manualAuth();
