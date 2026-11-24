import {
  getAuthorizationServerMetadata,
  getIssuer,
  isMcpEnabled,
  notFound,
  oauthJson,
  oauthOptions,
} from '@/lib/mcp/oauth';

export const dynamic = 'force-dynamic';

/** RFC 8414 authorization server metadata for the MCP OAuth flow. */
export function GET(request: Request) {
  if (!isMcpEnabled()) {
    return notFound();
  }

  return oauthJson(getAuthorizationServerMetadata(getIssuer(request.headers)));
}

export function OPTIONS() {
  return oauthOptions();
}
