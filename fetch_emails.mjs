#!/usr/bin/env node

import {
    loadClient, ensureAuth, gmailClient, log,
    historyList, fetchMessage, getCurrentHistoryId,
} from './gmail_lib.mjs';

const MAX_EMAILS = 40;

async function fetchUnread24h(client) {
    const gmail = gmailClient(client);
    const afterEpoch = Math.floor((Date.now() - 24 * 60 * 60 * 1000) / 1000);
    const listRes = await gmail.users.messages.list({
        userId: 'me',
        q: `after:${afterEpoch} in:inbox is:unread`,
        maxResults: MAX_EMAILS,
    });
    const messages = listRes.data.messages || [];
    const emails = [];
    for (const m of messages) emails.push(await fetchMessage(client, m.id));
    return emails;
}

async function fetchSinceHistory(client, sinceId) {
    const result = await historyList(client, sinceId);
    if (result.stale) {
        const current = await getCurrentHistoryId(client);
        return { emails: [], historyId: current, stale: true };
    }
    const emails = [];
    for (const id of result.addedMessageIds.slice(0, MAX_EMAILS)) {
        try {
            emails.push(await fetchMessage(client, id));
        } catch (err) {
            log(`fetchMessage failed for ${id}: ${err.message}`);
        }
    }
    return { emails, historyId: result.historyId, stale: false };
}

function parseArgs(argv) {
    const args = { mode: 'batch', sinceHistory: null };
    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === '--since-history') {
            args.mode = 'history';
            args.sinceHistory = argv[++i];
        }
    }
    return args;
}

(async () => {
    try {
        const args = parseArgs(process.argv);
        const client = await loadClient();
        await ensureAuth(client);
        if (args.mode === 'history') {
            const out = await fetchSinceHistory(client, args.sinceHistory);
            process.stdout.write(JSON.stringify(out));
        } else {
            const emails = await fetchUnread24h(client);
            process.stdout.write(JSON.stringify(emails));
        }
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
