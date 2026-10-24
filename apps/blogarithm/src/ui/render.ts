import type { Session, User } from '../domain/users.ts';

/** View context every page render receives. */
export interface RenderCtx {
  user?: User;
  session?: Session;
  flash?: { kind: 'info' | 'error' | 'ok'; text: string };
}
