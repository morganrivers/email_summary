#!/usr/bin/env node

import { loadClient, ensureAuth, findThreadByFromSubject, log } from './gmail_lib.mjs';

function parseArgs(argv) {
    const out = { fromEmail: null, subject: '' };
    for (let i = 2; i < argv.length; i++) {
        if (argv[i] === '--from') out.fromEmail = argv[++i];
        if (argv[i] === '--subject') out.subject = argv[++i];
    }
    return out;
}

(async () => {
    try {
        const args = parseArgs(process.argv);
        if (!args.fromEmail) throw new Error('--from required');
        const client = await loadClient();
        await ensureAuth(client);
        const result = await findThreadByFromSubject(client, args.fromEmail, args.subject);
        process.stdout.write(JSON.stringify(result));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
