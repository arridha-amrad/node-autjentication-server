// eslint-disable-next-line no-unused-vars
import session from 'express-session';
import { SessionUser } from '../src/dto/AuthData';

declare module 'express-session' {
  export interface SessionData {
    user: SessionUser;
    registerId: string;
  }
}
