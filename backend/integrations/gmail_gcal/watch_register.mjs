#!/usr/bin/env node

/**
 * Per-account users.watch worker (Track C2). Reads the account's creds from
 * GMAIL_MCP_DIR (set per user by node_runner.node_env), registers the Gmail
 * push watch via gmail_lib.registerWatch, and prints {historyId, expiration}
 * as one JSON line to stdout. It writes no state file: the Python driver
 * (watch_renew.py) owns the state schema so cursor writes stay single-sourced
 * in state.py.
 */

import { loadClient, ensureAuth, registerWatch, log } from './gmail_lib.mjs';

const TOPIC = process.env.GMAIL_PUBSUB_TOPIC
    || 'projects/coastal-mender-462719-q3/topics/gmail-events';

(async () => {
    const client = await loadClient();
    await ensureAuth(client);
    const res = await registerWatch(client, TOPIC);
    process.stdout.write(JSON.stringify({
        historyId: String(res.historyId),
        expiration: String(res.expiration),
    }) + '\n');
    const expDate = new Date(Number(res.expiration)).toISOString();
    log(`Watch registered. historyId=${res.historyId}, expires=${expDate}`);
})().catch((err) => {
    log('Error: ' + err.message);
    process.exit(1);
});
