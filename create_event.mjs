#!/usr/bin/env node

import { loadClient, ensureAuth, createCalendarEvent, log } from './gmail_lib.mjs';

function readStdin() {
    return new Promise((resolve, reject) => {
        let data = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', chunk => { data += chunk; });
        process.stdin.on('end', () => resolve(data));
        process.stdin.on('error', reject);
    });
}

(async () => {
    try {
        const input = JSON.parse(await readStdin());
        const { summary, startIso, endIso, timeZone, location, description } = input;
        if (!summary || !startIso || !endIso) {
            throw new Error('Missing required fields: summary, startIso, endIso');
        }
        const client = await loadClient();
        await ensureAuth(client);
        const event = await createCalendarEvent(client, {
            summary, startIso, endIso, timeZone, location, description,
        });
        process.stdout.write(JSON.stringify(event));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
