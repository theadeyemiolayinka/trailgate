import type { Cart } from '../domain/cart.ts';
import type { Session, User } from '../domain/users.ts';

/** View context every page render receives. */
export interface RenderCtx {
  user?: User;
  session?: Session;
  cart?: Cart;
  flash?: { kind: 'info' | 'error' | 'ok'; text: string };
}
