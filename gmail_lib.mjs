import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import path from 'path';
import fs from 'fs';
import http from 'http';
import os from 'os';

const requireBase = os.userInfo().username === 'dmrivers'
    ? path.join(os.homedir(), 'gmail-mcp-server', 'package.json')
    : fileURLToPath(import.meta.url);
const require = createRequire(requireBase);

const { OAuth2Client } = require('google-auth-library');
const { google } = require('googleapis');
const open = require('open');

export const CONFIG_DIR = process.env.GMAIL_MCP_DIR || path.join(os.homedir(), '.gmail-mcp');
export const OAUTH_PATH = path.join(CONFIG_DIR, 'gcp-oauth.keys.json');
export const CREDENTIALS_PATH = path.join(CONFIG_DIR, 'credentials.json');

export const SCOPES = [
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.settings.basic',
    'https://www.googleapis.com/auth/calendar.events',
];

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
    const keys = JSON.parse(fs.readFileSync(OAUTH_PATH, 'utf8'));
    const k = keys.installed || keys.web;
    const client = new OAuth2Client(k.client_id, k.client_secret, 'http://localhost:3000/oauth2callback');
    if (fs.existsSync(CREDENTIALS_PATH)) {
        client.setCredentials(JSON.parse(fs.readFileSync(CREDENTIALS_PATH, 'utf8')));
    }
    return client;
}

async function browserAuth(client) {
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
        open.default(authUrl).catch(() => log('Could not open browser automatically — visit the URL above.'));
        server.on('request', async (req, res) => {
            if (!req.url?.startsWith('/oauth2callback')) return;
            const url = new URL(req.url, 'http://localhost:3000');
            const code = url.searchParams.get('code');
            if (!code) { res.writeHead(400); res.end('No code'); reject(new Error('No code')); return; }
            try {
                const { tokens } = await client.getToken(code);
                client.setCredentials(tokens);
                fs.writeFileSync(CREDENTIALS_PATH, JSON.stringify(tokens, null, 2));
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

export async function ensureAuth(client) {
    try {
        const gmail = google.gmail({ version: 'v1', auth: client });
        await gmail.users.getProfile({ userId: 'me' });
    } catch (err) {
        if (err.code === 401 || err.message?.includes('invalid_grant') || err.message?.includes('Token has been expired')) {
            await browserAuth(client);
        } else {
            throw err;
        }
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
