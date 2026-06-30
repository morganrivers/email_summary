#!/usr/bin/env node

import { loadClient, ensureAuth, gmailClient, log } from './gmail_lib.mjs';

function readStdin() {
    return new Promise((resolve, reject) => {
        let data = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', chunk => { data += chunk; });
        process.stdin.on('end', () => resolve(data));
        process.stdin.on('error', reject);
    });
}

function encodeHeader(value) {
    if (/[^\x20-\x7e]/.test(value)) {
        return '=?UTF-8?B?' + Buffer.from(value, 'utf8').toString('base64') + '?=';
    }
    return value;
}

function buildRfc822({ to, subject, body, inReplyTo, references }) {
    const headers = [
        `To: ${encodeHeader(to)}`,
        `Subject: ${encodeHeader(subject)}`,
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
    ];
    if (inReplyTo) headers.push(`In-Reply-To: ${inReplyTo}`);
    if (references) headers.push(`References: ${references}`);
    return headers.join('\r\n') + '\r\n\r\n' + body;
}

function base64UrlEncode(str) {
    return Buffer.from(str, 'utf8').toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, '');
}

(async () => {
    try {
        const input = JSON.parse(await readStdin());
        const { to, subject, body, threadId, inReplyTo, references } = input;
        if (!to || !subject || !body) throw new Error('Missing required fields: to, subject, body');

        const client = await loadClient();
        await ensureAuth(client);
        const gmail = gmailClient(client);

        const raw = base64UrlEncode(buildRfc822({ to, subject, body, inReplyTo, references }));
        const messageRequest = { raw };
        if (threadId) messageRequest.threadId = threadId;

        const result = await gmail.users.drafts.create({
            userId: 'me',
            requestBody: { message: messageRequest },
        });
        process.stdout.write(JSON.stringify({ draftId: result.data.id }));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
