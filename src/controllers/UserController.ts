import { NextFunction, Request, Response } from 'express';
import ServerErrorException from '../exceptions/ServerErrorException';
import * as UserServices from '../services/UserServices';
import { getUserIdFromCookie } from '../utils/CookieHelpers';

export const me = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const userId = getUserIdFromCookie(req);
    const user = await UserServices.findUserById(
      userId,
      '_id username fullName avatarURL email'
    );
    return res.status(200).json({ user });
  } catch (err) {
    console.log(err);
    return next(new ServerErrorException());
  }
};
