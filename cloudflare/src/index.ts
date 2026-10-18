import { Container } from '@cloudflare/containers';
import { containerEnvironment, handleRequest, type RuntimeEnv } from './routing.ts';

export class IamContainer extends Container<RuntimeEnv> {
  defaultPort = 4000;
  sleepAfter = '1h';
  enableInternet = true;
  envVars: Record<string, string>;

  constructor(ctx: DurableObjectState<{}>, env: RuntimeEnv) {
    super(ctx, env);
    this.envVars = containerEnvironment(env);
  }
}

export default {
  fetch(request: Request, env: RuntimeEnv): Promise<Response> {
    return handleRequest(request, env);
  },
} satisfies ExportedHandler<RuntimeEnv>;
