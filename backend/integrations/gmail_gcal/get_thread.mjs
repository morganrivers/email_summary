#!/usr/bin/env node

import { loadClient, ensureAuth, getThread, log } from './gmail_lib.mjs';

function parseArgs(argv) {
    const out = { threadId: null };
    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === '--thread-id') out.threadId = argv[++i];
    }
    return out;
}

(async () => {
    try {
        const args = parseArgs(process.argv);
        if (!args.threadId) throw new Error('--thread-id required');
        const client = await loadClient();
        await ensureAuth(client);
        const thread = await getThread(client, args.threadId);
        process.stdout.write(JSON.stringify(thread));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
