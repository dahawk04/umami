import {
  isMcpEnabled,
  notFound,
  oauthJson,
  oauthOptions,
  type RegistrationFailure,
  type RegistrationSuccess,
  registerClient,
} from '@/lib/mcp/oauth';

export const dynamic = 'force-dynamic';

/** RFC 7591 dynamic client registration for MCP clients. */
export async function POST(request: Request) {
  if (!isMcpEnabled()) {
    return notFound();
  }

  let metadata: unknown;

  try {
    metadata = await request.json();
  } catch {
    return oauthJson(
      { error: 'invalid_client_metadata', error_description: 'Body must be JSON.' },
      400,
    );
  }

  const result = registerClient(metadata);

  if (result.ok === false) {
    const failure = result as RegistrationFailure;

    return oauthJson({ error: failure.error, error_description: failure.description }, 400);
  }

  return oauthJson((result as RegistrationSuccess).body, 201);
}

export function OPTIONS() {
  return oauthOptions();
}
