import { NextFunction, Request, Response } from 'express';
import ServerErrorException from '../exceptions/ServerErrorException';
import { IUserModel } from '../interfacesAndTypes/IUserModel';
import * as UserServices from '../services/UserServices';

export const me = async (req: Request, res: Response, next: NextFunction) => {
  try {
    let user: IUserModel | null = null;
    if (req.userId) {
      user = await UserServices.findUserById(
        req.userId,
        '_id username fullName avatarURL email'
      );
    }
    return res.status(200).json({ user });
  } catch (err) {
    console.log(err);
    return next(new ServerErrorException());
  }
};
