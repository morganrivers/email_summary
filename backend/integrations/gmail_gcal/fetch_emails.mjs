#!/usr/bin/env node

import {
    loadClient, ensureAuth, gmailClient, log,
    historyList, fetchMessage, getCurrentHistoryId,
    listCalendarEvents,
} from './gmail_lib.mjs';

const MAX_EMAILS = 40;
const XHAIN_CALENDAR_ID = 'isdrlmn4d5jmagpmta3igf4g0l0pjn9i@import.calendar.google.com';

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

async function fetchIds(client, ids) {
    const out = [];
    for (const id of ids.slice(0, MAX_EMAILS)) {
        try {
            out.push(await fetchMessage(client, id));
        } catch (err) {
            log(`fetchMessage failed for ${id}: ${err.message}`);
        }
    }
    return out;
}

async function fetchSinceHistory(client, sinceId) {
    const result = await historyList(client, sinceId);
    if (result.stale) {
        const current = await getCurrentHistoryId(client);
        return { emails: [], sent: [], historyId: current, stale: true };
    }
    const emails = await fetchIds(client, result.addedMessageIds);
    const sent = await fetchIds(client, result.sentMessageIds);
    return { emails, sent, historyId: result.historyId, stale: false };
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
            const nowIso = new Date().toISOString();
            const endIso = new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString();
            const events = await listCalendarEvents(client, nowIso, endIso, 50);
            let community_events = [];
            try {
                community_events = await listCalendarEvents(client, nowIso, endIso, 50, XHAIN_CALENDAR_ID);
            } catch (err) {
                log('xhain calendar fetch failed: ' + err.message);
            }
            process.stdout.write(JSON.stringify({ emails, events, community_events }));
        }
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
