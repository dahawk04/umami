import { isApiKey, isApiKeyEnabled } from '@/lib/api-key';
import { checkApiKeyAuth } from '@/lib/auth';
import {
  createRefreshToken,
  exchangeToken,
  isMcpEnabled,
  notFound,
  oauthJson,
  oauthOptions,
  type TokenFailure,
  type TokenSuccess,
} from '@/lib/mcp/oauth';

export const dynamic = 'force-dynamic';

async function readParams(request: Request) {
  const contentType = request.headers.get('content-type') ?? '';

  if (contentType.includes('application/json')) {
    const body = await request.json().catch(() => ({}));

    return new URLSearchParams(
      Object.entries(body ?? {}).map(([key, value]) => [key, String(value)]),
    );
  }

  return new URLSearchParams(await request.text());
}

/** OAuth token endpoint: the access token is the Umami API key the user approved. */
export async function POST(request: Request) {
  if (!isMcpEnabled()) {
    return notFound();
  }

  const result = exchangeToken(await readParams(request));

  if (result.ok === false) {
    const failure = result as TokenFailure;

    return oauthJson(
      { error: failure.error, error_description: failure.description },
      failure.status,
    );
  }

  const grant = result as TokenSuccess;

  // The key may have been deleted since it was approved; make the client sign in again.
  const auth =
    isApiKeyEnabled() && isApiKey(grant.apiKey)
      ? await checkApiKeyAuth(request, grant.apiKey)
      : null;

  if (!auth?.user?.id) {
    return oauthJson(
      { error: 'invalid_grant', error_description: 'The approved API key no longer exists.' },
      400,
    );
  }

  return oauthJson({
    access_token: grant.apiKey,
    token_type: 'Bearer',
    refresh_token: createRefreshToken(grant.clientId, grant.apiKey),
  });
}

export function OPTIONS() {
  return oauthOptions();
}
