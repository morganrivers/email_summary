#!/usr/bin/env node

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { loadClient, ensureAuth, gmailClient, log } from './gmail_lib.mjs';

const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const STATE_FILE = path.join(SCRIPT_DIR, 'state.json');
const TOPIC = process.env.GMAIL_PUBSUB_TOPIC
    || 'projects/coastal-mender-462719-q3/topics/gmail-events';

function loadState() {
    if (!fs.existsSync(STATE_FILE)) return { lastHistoryId: null, watchExpiration: null };
    return JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
}

function saveState(s) {
    fs.writeFileSync(STATE_FILE, JSON.stringify(s, null, 2));
}

(async () => {
    try {
        const client = await loadClient();
        await ensureAuth(client);
        const gmail = gmailClient(client);
        const res = await gmail.users.watch({
            userId: 'me',
            requestBody: {
                topicName: TOPIC,
                labelIds: ['INBOX'],
                labelFilterAction: 'include',
            },
        });
        const state = loadState();
        state.lastHistoryId = String(res.data.historyId);
        state.watchExpiration = String(res.data.expiration);
        saveState(state);
        const expDate = new Date(Number(res.data.expiration)).toISOString();
        log(`Watch registered. historyId=${res.data.historyId}, expires=${expDate}`);
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
