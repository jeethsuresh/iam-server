export interface Settings {
  IAM_DOMAIN: string;
  IAM_PUBLIC_URL: string;
}
export interface RuntimeEnv extends Settings {
  IAM: { getByName(name: string): { fetch(request: Request): Promise<Response> } };
  DATABASE_URL: string;
  JWT_SECRET: string;
  SECRET_KEY_BASE: string;
  IAM_ADMIN_USERNAME?: string;
  IAM_ADMIN_PASSWORD?: string;
  MATRIX_DOMAIN?: string;
  R2_ENDPOINT?: string;
  R2_BUCKET?: string;
  R2_ACCESS_KEY_ID?: string;
  R2_SECRET_ACCESS_KEY?: string;
}
const discoveryPaths = new Set([
  '/.well-known/webfinger', '/.well-known/iam-configuration', '/.well-known/matrix/client',
]);

export function publicOrigin(env: Settings): URL {
  const issuer = new URL(env.IAM_PUBLIC_URL);
  if (issuer.protocol !== 'https:' || issuer.pathname !== '/' || issuer.search ||
      issuer.hash || issuer.username || issuer.password || !env.IAM_DOMAIN ||
      !/^[a-z0-9.-]+$/.test(env.IAM_DOMAIN)) {
    throw new Error('Configure IAM_PUBLIC_URL as an HTTPS origin and IAM_DOMAIN as a DNS name');
  }
  return issuer;
}

export function containerEnvironment(env: RuntimeEnv): Record<string, string> {
  const issuer = publicOrigin(env);
  for (const name of ['DATABASE_URL', 'JWT_SECRET', 'SECRET_KEY_BASE', 'IAM_ADMIN_PASSWORD'] as const) {
    if (!env[name]) throw new Error(`Missing ${name} Worker secret`);
  }
  if (env.JWT_SECRET.length < 32 || env.SECRET_KEY_BASE.length < 64) {
    throw new Error('JWT_SECRET needs 32 characters; SECRET_KEY_BASE needs 64');
  }
  if (env.IAM_ADMIN_PASSWORD!.length < 12) throw new Error('IAM_ADMIN_PASSWORD needs 12 characters');
  const result: Record<string, string> = {
    IAM_DOMAIN: env.IAM_DOMAIN,
    IAM_PUBLIC_URL: issuer.origin,
    MATRIX_DOMAIN: env.MATRIX_DOMAIN || env.IAM_DOMAIN,
    DATABASE_URL: env.DATABASE_URL,
    DATABASE_SSL: 'verify-full', IAM_EPHEMERAL_DISK: 'true',
    JWT_SECRET: env.JWT_SECRET,
    SECRET_KEY_BASE: env.SECRET_KEY_BASE,
    IAM_ADMIN_USERNAME: env.IAM_ADMIN_USERNAME || 'admin',
    IAM_ADMIN_PASSWORD: env.IAM_ADMIN_PASSWORD || '',
    PHX_SERVER: 'true', PORT: '4000', RELEASE_DISTRIBUTION: 'none',
  };
  for (const name of ['R2_ENDPOINT', 'R2_BUCKET', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY'] as const) {
    if (env[name]) result[name] = env[name];
  }
  return result;
}

export async function handleRequest(request: Request, env: RuntimeEnv): Promise<Response> {
  const issuer = publicOrigin(env);
  const url = new URL(request.url);
  if (url.host !== issuer.host) {
    if (url.host === env.IAM_DOMAIN && discoveryPaths.has(url.pathname) &&
        ['GET', 'HEAD'].includes(request.method)) {
      return new Response(null, { status: 307, headers: {
        Location: issuer.origin + url.pathname + url.search,
        'Access-Control-Allow-Origin': '*',
        'Cache-Control': 'public, max-age=300',
      }});
    }
    return new Response('Unknown identity host', { status: 404 });
  }
  if (url.protocol !== 'https:') {
    return new Response(null, { status: 308, headers: { Location: issuer.origin + url.pathname + url.search }});
  }
  const forwarded = new Request(request);
  forwarded.headers.delete('forwarded');
  forwarded.headers.set('x-forwarded-proto', 'https');
  forwarded.headers.set('x-forwarded-host', issuer.host);
  forwarded.headers.set('x-forwarded-port', '443');
  // OTP room actors and PubSub require one stable instance. Never use a random ID here.
  return env.IAM.getByName('iam-primary').fetch(forwarded);
}
