import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import http from 'http';
import os from 'os';

const require = createRequire(fileURLToPath(import.meta.url));

const { OAuth2Client } = require('google-auth-library');
const { google } = require('googleapis');

export const CONFIG_DIR = process.env.GMAIL_MCP_DIR || path.join(os.homedir(), '.gmail-mcp');
export const OAUTH_PATH = path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
export const CREDENTIALS_PATH = path.join(CONFIG_DIR, 'credentials.json');

// One OAuth app serves every user, so its client_secret lives in exactly one
// file. It used to be copied into each account's creds directory, which turned
// a single leaked user directory into a leak of the whole app.
// Order: explicit env, then the box-level keys beside the app, then (for a
// single-tenant checkout with no box-level copy) the account's own directory.
const APP_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const SHARED_KEYS = path.join(APP_ROOT, '.gmail-mcp', 'gcp-oauth.keys.json');
export const OAUTH_KEYS_PATH = process.env.GMAIL_OAUTH_KEYS
    || (fs.existsSync(SHARED_KEYS) ? SHARED_KEYS : OAUTH_PATH);

// Public redirect URI Google sends the consent code back to. The hosted web
// flow registers this exact value; the localhost default is the loopback used
// by the manual_auth CLI.
export const OAUTH_REDIRECT_URI = process.env.GMAIL_OAUTH_REDIRECT_URI
    || 'http://localhost:3000/oauth2callback';

// openid/email/profile grant the login identity (name + email) alongside the
// Gmail/Calendar scopes, so one consent yields both the account and the token.
// Ask for nothing beyond what the code calls: gmail.settings.basic was
// requested and never used, and an unused scope is only ever a bigger loss when
// a token leaks.
export const SCOPES = [
    'openid',
    'email',
    'profile',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/calendar.events',
];

// Same names backend/secrets.py exports, which is where the Python side reads
// them. One OAuth app serves every user, so its client_secret has the widest
// blast radius of any value here: inside the enclave it arrives as injected
// environment, decrypted post-attestation, and the file path below is refused
// outright. A file on the volume is a copy the KMS does not gate.
const TEE_REQUIRED = ['1', 'true', 'yes']
    .includes((process.env.TEE_REQUIRED || '').trim().toLowerCase());

export function loadOAuthKeys() {
    const injected = {
        client_id: process.env.GOOGLE_OAUTH_CLIENT_ID,
        client_secret: process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    };
    if (injected.client_id && injected.client_secret) return injected;
    if (TEE_REQUIRED) {
        throw new Error('GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET were not '
            + 'injected; refusing to read the OAuth client secret off the volume');
    }
    const keys = JSON.parse(fs.readFileSync(OAUTH_KEYS_PATH, 'utf8'));
    const k = keys.installed || keys.web;
    if (!k?.client_id || !k?.client_secret) {
        throw new Error(`OAuth keys at ${OAUTH_KEYS_PATH} missing client_id/client_secret`);
    }
    return k;
}

// OAuth client for the hosted web flow: same app keys, but the public
// redirect URI instead of the loopback. Sole constructor for the onboarding
// code exchange so client config stays single-sourced.
export function makeWebClient(redirectUri = OAUTH_REDIRECT_URI) {
    const k = loadOAuthKeys();
    return new OAuth2Client(k.client_id, k.client_secret, redirectUri);
}

export function log(msg) {
    process.stderr.write(msg + '\n');
}

export function extractText(part) {
    if (!part) return '';
    if (part.mimeType === 'text/plain' && part.body?.data) {
        return Buffer.from(part.body.data, 'base64').toString('utf8');
    }
    if (part.parts) {
        for (const p of part.parts) {
            const t = extractText(p);
            if (t) return t;
        }
    }
    return '';
}

export async function loadClient() {
    const k = loadOAuthKeys();
    const client = new OAuth2Client(k.client_id, k.client_secret, OAUTH_REDIRECT_URI);
    if (fs.existsSync(CREDENTIALS_PATH)) {
        client.setCredentials(JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8')));
    }
    return client;
}

// Opening a browser is only ever right on a laptop. On the server it bound
// :3000 and waited forever for a callback that could not arrive, so one user
// with a revoked grant burned every subprocess timeout and collided with any
// other account doing the same. manual_auth.mjs sets this deliberately.
const INTERACTIVE_AUTH = process.env.GMAIL_INTERACTIVE_AUTH === '1';

export class ReauthRequired extends Error {
    constructor(credsDir) {
        super(`Gmail credentials at ${credsDir} are no longer valid; the account must re-consent`);
        this.name = 'ReauthRequired';
        this.credsDir = credsDir;
    }
}

async function browserAuth(client) {
    // Imported here rather than at module load: `open` is only reachable on the
    // interactive path, and every server-side script imports this file.
    const { default: open } = await import('open');
    const server = http.createServer();
    server.listen(3000);
    return new Promise((resolve, reject) => {
        const authUrl = client.generateAuthUrl({
            access_type: 'offline',
            scope: SCOPES,
            prompt: 'consent',
        });
        log('Tokens expired. Opening browser for re-auth...');
        log('Auth URL: ' + authUrl);
        open(authUrl).catch(() => log('Could not open browser automatically; visit the URL above.'));
        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;
            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');
            if (!code) { res.writeHead(400); res.end('No code'); reject(new Error('No code')); return; }
            try {
                const { tokens } = await client.getToken(code);
                client.setCredentials(tokens);
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens, null, 2), { mode: 0o600 });
                res.writeHead(200);
                res.end('Authenticated! You can close this window.');
                server.close();
                log('Re-auth successful.');
                resolve();
            } catch (err) {
                res.writeHead(500); res.end('Auth failed');
                reject(err);
            }
        });
    });
}

function isAuthFailure(err) {
    return err.code === 401
        || err.message?.includes('invalid_grant')
        || err.message?.includes('Token has been expired')
        || err.message?.includes('No access, refresh token');
}

export async function ensureAuth(client) {
    try {
        const gmail = google.gmail({ version: 'v1', auth: client });
        await gmail.users.getProfile({ userId: 'me' });
    } catch (err) {
        if (!isAuthFailure(err)) throw err;
        if (!INTERACTIVE_AUTH) throw new ReauthRequired(CONFIG_DIR);
        await browserAuth(client);
    }
}

export function gmailClient(client) {
    return google.gmail({ version: 'v1', auth: client });
}

export function calendarClient(client) {
    return google.calendar({ version: 'v3', auth: client });
}

function normalizeBody(text) {
    return text
        .replace(/\r\n/g, '\n')
        .replace(/[ \t]+/g, ' ')
        .replace(/\n{3,}/g, '\n\n')
        .trim();
}

export async function searchMessages(client, query, maxResults = 5) {
    const gmail = gmailClient(client);
    const listRes = await gmail.users.messages.list({
        userId: 'me',
        q: query,
        maxResults,
    });
    const messages = listRes.data.messages || [];
    const results = [];
    for (const m of messages) {
        const full = await gmail.users.messages.get({ userId: 'me', id: m.id, format: 'full' });
        const headers = {};
        for (const h of full.data.payload?.headers || []) {
            headers[h.name.toLowerCase()] = h.value;
        }
        const body = normalizeBody(extractText(full.data.payload));
        results.push({
            id: m.id,
            threadId: full.data.threadId,
            from: headers['from'] || '',
            to: headers['to'] || '',
            subject: headers['subject'] || '',
            date: headers['date'] || '',
            snippet: full.data.snippet || '',
            body: body.slice(0, 2000),
        });
    }
    return results;
}

export async function getThread(client, threadId) {
    const gmail = gmailClient(client);
    const res = await gmail.users.threads.get({ userId: 'me', id: threadId, format: 'full' });
    const messages = [];
    for (const msg of res.data.messages || []) {
        const headers = {};
        for (const h of msg.payload?.headers || []) {
            headers[h.name.toLowerCase()] = h.value;
        }
        messages.push({
            id: msg.id,
            from: headers['from'] || '',
            to: headers['to'] || '',
            subject: headers['subject'] || '',
            date: headers['date'] || '',
            body: normalizeBody(extractText(msg.payload)).slice(0, 3000),
        });
    }
    return { threadId, messages };
}

// Sole source of the reply-triage participation signal. Gmail's own SENT label
// records that the account owner wrote in the thread, so this needs no address
// matching and cannot disagree with what the mailbox shows.
export async function threadHasUserMessage(client, threadId, excludeMessageId) {
    const gmail = gmailClient(client);
    const res = await gmail.users.threads.get({ userId: 'me', id: threadId, format: 'minimal' });
    for (const msg of res.data.messages || []) {
        if (msg.id === excludeMessageId) continue;
        if ((msg.labelIds || []).includes('SENT')) return true;
    }
    return false;
}

// Annotates inbound emails in place with userParticipated. One failed lookup
// degrades that email to the pre-existing "no participation signal" behavior
// rather than losing the whole batch.
export async function annotateThreadParticipation(client, emails) {
    for (const e of emails) {
        if (!e.threadId) {
            e.userParticipated = false;
            continue;
        }
        try {
            e.userParticipated = await threadHasUserMessage(client, e.threadId, e.id);
        } catch (err) {
            log(`thread participation lookup failed for ${e.id}: ${err.message}`);
            e.userParticipated = false;
        }
    }
    return emails;
}

export async function listCalendarEvents(client, startIso, endIso, maxResults = 50, calendarId = 'primary') {
    const cal = calendarClient(client);
    const res = await cal.events.list({
        calendarId,
        timeMin: startIso,
        timeMax: endIso,
        singleEvents: true,
        orderBy: 'startTime',
        maxResults,
    });
    return (res.data.items || []).map(e => ({
        id: e.id,
        summary: e.summary || '(no title)',
        start: e.start?.dateTime || e.start?.date || '',
        end: e.end?.dateTime || e.end?.date || '',
        location: e.location || '',
        description: (e.description || '').slice(0, 500),
        attendees: (e.attendees || []).map(a => a.email),
    }));
}

export async function createCalendarEvent(client, {
    summary, startIso, endIso, timeZone = 'Europe/Berlin',
    location = '', description = '', calendarId = 'primary',
}) {
    if (!summary || !startIso || !endIso) {
        throw new Error('createCalendarEvent requires summary, startIso, endIso');
    }
    const cal = calendarClient(client);
    const requestBody = {
        summary,
        start: { dateTime: startIso, timeZone },
        end: { dateTime: endIso, timeZone },
    };
    if (location) requestBody.location = location;
    if (description) requestBody.description = description;
    const res = await cal.events.insert({
        calendarId,
        requestBody,
        sendUpdates: 'none',
    });
    return { id: res.data.id, htmlLink: res.data.htmlLink || '' };
}

export async function findThreadByFromSubject(client, fromEmail, subject) {
    const cleanSubject = (subject || '').replace(/^(re:|fwd:|fw:)\s*/gi, '').trim();
    let q = `from:${fromEmail}`;
    if (cleanSubject) q += ` subject:"${cleanSubject.replace(/"/g, '\\"')}"`;
    const gmail = gmailClient(client);
    const listRes = await gmail.users.messages.list({
        userId: 'me',
        q,
        maxResults: 5,
    });
    const messages = listRes.data.messages || [];
    if (messages.length === 0) return { found: false };
    const full = await gmail.users.messages.get({ userId: 'me', id: messages[0].id, format: 'full' });
    const headers = {};
    for (const h of full.data.payload?.headers || []) {
        headers[h.name.toLowerCase()] = h.value;
    }
    return {
        found: true,
        threadId: full.data.threadId,
        messageIdHeader: headers['message-id'] || '',
        referencesHeader: headers['references'] || '',
        subject: headers['subject'] || '',
        from: headers['from'] || '',
    };
}

export async function historyList(client, startHistoryId) {
    const gmail = gmailClient(client);
    const added = [];
    const sent = [];
    let pageToken;
    let latestHistoryId = startHistoryId;
    do {
        let res;
        try {
            res = await gmail.users.history.list({
                userId: 'me',
                startHistoryId,
                historyTypes: ['messageAdded'],
                pageToken,
            });
        } catch (err) {
            if (err.code === 404) {
                return { addedMessageIds: [], sentMessageIds: [], historyId: null, stale: true };
            }
            throw err;
        }
        for (const h of res.data.history || []) {
            for (const ma of h.messagesAdded || []) {
                const m = ma.message;
                const labels = m.labelIds || [];
                if (labels.includes('INBOX')) {
                    added.push(m.id);
                } else if (labels.includes('SENT')) {
                    sent.push(m.id);
                }
            }
        }
        if (res.data.historyId) latestHistoryId = res.data.historyId;
        pageToken = res.data.nextPageToken;
    } while (pageToken);
    return {
        addedMessageIds: [...new Set(added)],
        sentMessageIds: [...new Set(sent)],
        historyId: latestHistoryId,
        stale: false,
    };
}

export async function getCurrentHistoryId(client) {
    const gmail = gmailClient(client);
    const res = await gmail.users.getProfile({ userId: 'me' });
    return res.data.historyId;
}

// Sole users.watch call (Track C2). Both the CLI worker and the per-user
// renewal driver route through here, so the topic/label registration shape is
// defined in exactly one place. Returns the current historyId + watch expiry.
export async function registerWatch(client, topicName) {
    const gmail = gmailClient(client);
    const res = await gmail.users.watch({
        userId: 'me',
        requestBody: {
            topicName,
            labelIds: ['INBOX'],
            labelFilterAction: 'include',
        },
    });
    return { historyId: res.data.historyId, expiration: res.data.expiration };
}

export async function fetchMessage(client, id) {
    const gmail = gmailClient(client);
    const full = await gmail.users.messages.get({ userId: 'me', id, format: 'full' });
    const headers = {};
    for (const h of full.data.payload?.headers || []) {
        headers[h.name.toLowerCase()] = h.value;
    }
    const body = normalizeBody(extractText(full.data.payload));
    return {
        id,
        threadId: full.data.threadId,
        from: headers['from'] || 'unknown',
        to: headers['to'] || '',
        subject: headers['subject'] || '(no subject)',
        messageIdHeader: headers['message-id'] || '',
        referencesHeader: headers['references'] || '',
        date: headers['date'] || '',
        body,
    };
}
