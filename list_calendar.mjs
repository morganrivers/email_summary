#!/usr/bin/env node

import { loadClient, ensureAuth, listCalendarEvents, log } from './gmail_lib.mjs';

function parseArgs(argv) {
    const out = { startIso: null, endIso: null };
    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === '--start') out.startIso = argv[++i];
        if (argv[i] === '--end') out.endIso = argv[++i];
    }
    return out;
}

(async () => {
    try {
        const args = parseArgs(process.argv);
        if (!args.startIso || !args.endIso) throw new Error('--start and --end required (ISO 8601)');
        const client = await loadClient();
        await ensureAuth(client);
        const events = await listCalendarEvents(client, args.startIso, args.endIso, 50);
        process.stdout.write(JSON.stringify(events));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
