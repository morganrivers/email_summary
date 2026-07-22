#!/usr/bin/env node

import { loadClient, ensureAuth, gmailClient, log } from './gmail_lib.mjs';
import crypto from 'crypto';

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

function escapeHtml(s) {
    return s
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
}

function plainToHtml(s) {
    return escapeHtml(s).replace(/\r?\n/g, '<br>\n');
}

function plainQuote(originalBody) {
    return originalBody
        .replace(/\r\n/g, '\n')
        .split('\n')
        .map(l => '> ' + l)
        .join('\n');
}

function buildAttribution({ originalFrom, originalDate }) {
    const parts = [];
    if (originalDate) parts.push('On ' + originalDate + ',');
    if (originalFrom) parts.push(originalFrom);
    parts.push('wrote:');
    return parts.join(' ');
}

function hasQuote(o) {
    return !!(o.originalBody || o.originalFrom || o.originalDate);
}

function buildPlain(o) {
    if (!hasQuote(o)) return o.body;
    const header = buildAttribution(o);
    const quoted = o.originalBody ? plainQuote(o.originalBody) : '';
    return o.body + '\r\n\r\n' + header + '\r\n' + quoted;
}

function buildHtml(o) {
    const bodyHtml = '<div dir="ltr">' + plainToHtml(o.body) + '</div>';
    if (!hasQuote(o)) {
        return '<html><body>' + bodyHtml + '</body></html>';
    }
    const attribution = escapeHtml(buildAttribution(o));
    const quotedHtml = o.originalBody ? plainToHtml(o.originalBody) : '';
    const quoteBlock =
        '<div class="gmail_quote gmail_quote_container">' +
        '<div dir="ltr" class="gmail_attr">' + attribution + '<br></div>' +
        '<blockquote class="gmail_quote" ' +
        'style="margin:0 0 0 .8ex;border-left:1px solid #ccc;padding-left:1ex">' +
        quotedHtml +
        '</blockquote>' +
        '</div>';
    return '<html><body>' + bodyHtml + '<br>' + quoteBlock + '</body></html>';
}

function buildRfc822(o) {
    const boundary = 'BOUND_' + crypto.randomBytes(12).toString('hex');
    const headers = [
        `To: ${encodeHeader(o.to)}`,
        `Subject: ${encodeHeader(o.subject)}`,
        'MIME-Version: 1.0',
        `Content-Type: multipart/alternative; boundary="${boundary}"`,
    ];
    if (o.inReplyTo) headers.push(`In-Reply-To: ${o.inReplyTo}`);
    if (o.references) headers.push(`References: ${o.references}`);

    const plainPart =
        `--${boundary}\r\n` +
        'Content-Type: text/plain; charset=UTF-8\r\n' +
        'Content-Transfer-Encoding: 8bit\r\n\r\n' +
        buildPlain(o);

    const htmlPart =
        `--${boundary}\r\n` +
        'Content-Type: text/html; charset=UTF-8\r\n' +
        'Content-Transfer-Encoding: 8bit\r\n\r\n' +
        buildHtml(o);

    const closer = `--${boundary}--\r\n`;

    return headers.join('\r\n') + '\r\n\r\n' +
           plainPart + '\r\n\r\n' +
           htmlPart + '\r\n\r\n' +
           closer;
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
        const {
            to, subject, body, threadId, inReplyTo, references,
            originalFrom, originalDate, originalBody, draftId,
        } = input;
        if (!to || !subject || !body) throw new Error('Missing required fields: to, subject, body');

        const client = await loadClient();
        await ensureAuth(client);
        const gmail = gmailClient(client);

        const raw = base64UrlEncode(buildRfc822({
            to, subject, body, inReplyTo, references,
            originalFrom, originalDate, originalBody,
        }));
        const messageRequest = { raw };
        if (threadId) messageRequest.threadId = threadId;

        let result;
        if (draftId) {
            result = await gmail.users.drafts.update({
                userId: 'me',
                id: draftId,
                requestBody: { message: messageRequest },
            });
        } else {
            result = await gmail.users.drafts.create({
                userId: 'me',
                requestBody: { message: messageRequest },
            });
        }
        process.stdout.write(JSON.stringify({ draftId: result.data.id }));
    } catch (err) {
        log('Error: ' + err.message);
        process.exit(1);
    }
})();
