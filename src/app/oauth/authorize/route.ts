import { isApiKey, isApiKeyEnabled } from '@/lib/api-key';
import { checkApiKeyAuth } from '@/lib/auth';
import {
  type AuthorizeFailure,
  type AuthorizeParams,
  type AuthorizeRedirectFailure,
  type AuthorizeValidation,
  buildRedirect,
  createAuthorizationCode,
  getIssuer,
  isMcpEnabled,
  notFound,
  validateAuthorizeParams,
} from '@/lib/mcp/oauth';

export const dynamic = 'force-dynamic';

const FORWARDED_PARAMS = [
  'response_type',
  'client_id',
  'redirect_uri',
  'code_challenge',
  'code_challenge_method',
  'state',
  'scope',
  'resource',
];

function escapeHtml(value: string) {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function page(body: string, status = 200) {
  const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>Connect to Umami</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; font: 16px/1.5 system-ui, -apple-system, sans-serif; display: grid; place-items: center; min-height: 100vh; padding: 16px; box-sizing: border-box; }
  main { width: 100%; max-width: 420px; }
  h1 { font-size: 22px; margin: 0 0 8px; }
  p { margin: 0 0 16px; opacity: .8; }
  label { display: block; font-weight: 600; margin-bottom: 6px; }
  input[type=password] { width: 100%; box-sizing: border-box; padding: 12px; font: inherit; border-radius: 8px; border: 1px solid #8888; background: transparent; color: inherit; }
  button { margin-top: 16px; width: 100%; padding: 12px; font: inherit; font-weight: 600; border: 0; border-radius: 8px; background: #2680eb; color: #fff; cursor: pointer; }
  .error { color: #d7373f; opacity: 1; }
  code { font-size: 14px; }
</style>
</head>
<body><main>${body}</main></body>
</html>`;

  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store',
      'x-frame-options': 'DENY',
    },
  });
}

function errorPage(message: string) {
  return page(`<h1>Can't connect</h1><p class="error">${escapeHtml(message)}</p>`, 400);
}

function formPage(params: URLSearchParams, clientName: string | undefined, error?: string) {
  const hidden = FORWARDED_PARAMS.map(name => {
    const value = params.get(name);

    return value === null
      ? ''
      : `<input type="hidden" name="${name}" value="${escapeHtml(value)}">`;
  }).join('');

  const app = escapeHtml(clientName || 'An MCP client');

  return page(
    `<h1>Connect to Umami</h1>
<p><strong>${app}</strong> wants access to your Umami analytics. Paste an Umami API key
(Settings &rarr; API keys) to allow it. The app uses that key until you delete it.</p>
${error ? `<p class="error">${escapeHtml(error)}</p>` : ''}
<form method="post" autocomplete="off">
${hidden}
<label for="api_key">API key</label>
<input id="api_key" name="api_key" type="password" placeholder="umami_…" required autofocus>
<button type="submit">Allow access</button>
</form>`,
    error ? 400 : 200,
  );
}

function redirectTo(url: string) {
  return new Response(null, {
    status: 303,
    headers: { location: url, 'cache-control': 'no-store' },
  });
}

function handleInvalid(result: AuthorizeValidation, issuer: string) {
  const failure = result as AuthorizeFailure;

  if (failure.redirect === false) {
    return errorPage(failure.error);
  }

  const validation = failure as AuthorizeRedirectFailure;

  return redirectTo(
    buildRedirect(validation.redirectUri, {
      error: validation.error,
      error_description: validation.description,
      state: validation.state,
      iss: issuer,
    }),
  );
}

export function GET(request: Request) {
  if (!isMcpEnabled()) {
    return notFound();
  }

  if (!isApiKeyEnabled()) {
    return errorPage('API keys are not available on this Umami instance.');
  }

  const params = new URL(request.url).searchParams;
  const validation = validateAuthorizeParams(params);

  if (!validation.ok) {
    return handleInvalid(validation, getIssuer(request.headers));
  }

  return formPage(params, validation.client.clientName);
}

export async function POST(request: Request) {
  if (!isMcpEnabled()) {
    return notFound();
  }

  if (!isApiKeyEnabled()) {
    return errorPage('API keys are not available on this Umami instance.');
  }

  const form = new URLSearchParams(await request.text());
  const params = new URLSearchParams();

  for (const name of FORWARDED_PARAMS) {
    const value = form.get(name);

    if (value !== null) {
      params.set(name, value);
    }
  }

  const issuer = getIssuer(request.headers);
  const validation = validateAuthorizeParams(params);

  if (!validation.ok) {
    return handleInvalid(validation, issuer);
  }

  const apiKey = (form.get('api_key') ?? '').trim();
  const auth = isApiKey(apiKey) ? await checkApiKeyAuth(request, apiKey) : null;

  if (!auth?.user?.id) {
    return formPage(params, validation.client.clientName, 'That API key was not recognized.');
  }

  const authorizeParams: AuthorizeParams = validation.params;

  return redirectTo(
    buildRedirect(authorizeParams.redirectUri, {
      code: createAuthorizationCode(authorizeParams, apiKey),
      state: authorizeParams.state,
      iss: issuer,
    }),
  );
}
