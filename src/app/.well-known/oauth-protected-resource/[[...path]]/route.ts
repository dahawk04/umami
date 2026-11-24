import {
  getIssuer,
  getProtectedResourceMetadata,
  isMcpEnabled,
  notFound,
  oauthJson,
  oauthOptions,
} from '@/lib/mcp/oauth';

export const dynamic = 'force-dynamic';

/** RFC 9728 protected resource metadata for /mcp (also served at the /mcp-suffixed path). */
export function GET(request: Request) {
  if (!isMcpEnabled()) {
    return notFound();
  }

  return oauthJson(getProtectedResourceMetadata(getIssuer(request.headers)));
}

export function OPTIONS() {
  return oauthOptions();
}
