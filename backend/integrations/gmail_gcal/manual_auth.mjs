#!/usr/bin/env node
/**
 * Manual OAuth helper - prints URL, waits for callback code
 */

import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import fs from 'fs';
import readline from 'readline';

import {
    SCOPES, CONFIG_DIR, CREDENTIALS_PATH, OAUTH_REDIRECT_URI, loadOAuthKeys,
} from './gmail_lib.mjs';

const require = createRequire(fileURLToPath(import.meta.url));

const { OAuth2Client } = require('google-auth-library');

async function manualAuth() {
    const k = loadOAuthKeys();
    const client = new OAuth2Client(k.client_id, k.client_secret, OAUTH_REDIRECT_URI);

    const authUrl = client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
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
                fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
            }

            fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens, null, 2), { mode: 0o600 });
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
