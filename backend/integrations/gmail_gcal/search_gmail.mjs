#!/usr/bin/env node

import { loadClient, ensureAuth, searchMessages, log } from './gmail_lib.mjs';

function parseArgs(argv) {
    const out = { query: null, maxResults: 5 };
    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === '--query') out.query = argv[++i];
        if (argv[i] === '--max') out.maxResults = parseInt(argv[++i], 10);
    }
    return out;
}

(async () => {
    try {
        const args = parseArgs(process.argv);
        if (!args.query) throw new Error('--query required');
        const client = await loadClient();
        await ensureAuth(client);
        const results = await searchMessages(client, args.query, args.maxResults);
        process.stdout.write(JSON.stringify(results));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
