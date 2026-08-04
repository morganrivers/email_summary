#!/usr/bin/env node
/**
 * Onboarding OAuth helper (Track C1). Two subcommands the Python control plane
 * shells out to, mirroring how pipeline.py shells to fetch_emails.mjs:
 *
 *   oauth_helper.mjs auth-url --state <s> [--redirect <uri>]
 *       Prints the Google consent URL (one line, stdout).
 *
 *   oauth_helper.mjs exchange --code <c> --creds-dir <dir> [--redirect <uri>]
 *       Exchanges the one-time code for tokens, writes credentials.json into
 *       the per-user creds dir in the shape gmail_lib.loadClient reads, and
 *       prints the profile JSON {email, first, last} to stdout.
 *
 * All Google/OAuth concerns (app keys, scopes, redirect URI, token shape) live
 * in gmail_lib.mjs; this file only wires them to a CLI so the OAuth surface has
 * a single source of truth in Node while account/state writes stay in Python.
 */

import fs from 'fs';
import path from 'path';
import {
    SCOPES, OAUTH_REDIRECT_URI, makeWebClient, gmailClient, log,
} from './gmail_lib.mjs';

function parseArgs(argv) {
    const args = {};
    for (let i = 0; i < argv.length; i += 2) {
        const key = argv[i];
        if (!key.startsWith('--')) throw new Error(`unexpected arg ${key}`);
        args[key.slice(2)] = argv[i + 1];
    }
    return args;
}

function decodeIdToken(idToken) {
    if (!idToken) return {};
    const parts = idToken.split('.');
    if (parts.length < 2) return {};
    const json = Buffer.from(parts[1], 'base64').toString('utf8');
    return JSON.parse(json);
}

function splitName(claims, email) {
    let first = (claims.given_name || '').trim();
    let last = (claims.family_name || '').trim();
    if (!first && claims.name) {
        const parts = claims.name.trim().split(/\s+/);
        first = parts[0] || '';
        last = last || parts.slice(1).join(' ');
    }
    if (!first) first = (email.split('@')[0] || 'User');
    // UserIdentity requires a non-empty last name; fall back to the first name
    // so masking still tags the owner rather than failing onboarding.
    if (!last) last = first;
    return { first, last };
}

async function authUrl(args) {
    if (!args.state) throw new Error('auth-url requires --state');
    const client = makeWebClient(args.redirect || OAUTH_REDIRECT_URI);
    const url = client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
        prompt: 'consent',
        include_granted_scopes: true,
        state: args.state,
    });
    process.stdout.write(url + '\n');
}

async function exchange(args) {
    if (!args.code) throw new Error('exchange requires --code');
    if (!args['creds-dir']) throw new Error('exchange requires --creds-dir');
    const credsDir = args['creds-dir'];
    const client = makeWebClient(args.redirect || OAUTH_REDIRECT_URI);
    const { tokens } = await client.getToken(args.code);
    if (!tokens.refresh_token) {
        throw new Error('no refresh_token returned (prior grant without prompt=consent?)');
    }
    client.setCredentials(tokens);

    const gmail = gmailClient(client);
    const profile = await gmail.users.getProfile({ userId: 'me' });
    const email = (profile.data.emailAddress || '').trim().toLowerCase();
    if (!email) throw new Error('getProfile returned no emailAddress');
    const claims = decodeIdToken(tokens.id_token);
    const { first, last } = splitName(claims, email);

    // Only the tokens, and only readable by us. The app keys are NOT copied
    // here: one client_secret, one file (see OAUTH_KEYS_PATH in gmail_lib).
    fs.mkdirSync(credsDir, { recursive: true, mode: 0o700 });
    fs.chmodSync(credsDir, 0o700);
    fs.writeFileSync(
        path.join(credsDir, 'credentials.json'),
        JSON.stringify(tokens, null, 2),
        { mode: 0o600 },
    );

    process.stdout.write(JSON.stringify({ email, first, last }) + '\n');
}

const [, , cmd, ...rest] = process.argv;
const handlers = { 'auth-url': authUrl, exchange };
const handler = handlers[cmd];
if (!handler) {
    log(`usage: oauth_helper.mjs <auth-url|exchange> [--flag value ...]`);
    process.exit(2);
}
handler(parseArgs(rest)).catch((err) => {
    log('Error: ' + err.message);
    process.exit(1);
});
