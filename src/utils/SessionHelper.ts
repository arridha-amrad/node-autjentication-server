import { Request } from 'express';
import { SessionUser } from '../dto/AuthData';

export const setUserToSession = (data: SessionUser, req: Request) => {
  req.session.user = data;
};

export const getUserFromSession = (req: Request) => req.session.user;
