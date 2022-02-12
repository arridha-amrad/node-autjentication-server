import { Request, Response } from 'express';
import * as UserServices from '../services/UserServices';

export const me = async (req: Request, res: Response) => {
  console.log('request to me');

  try {
    const userId = req.userId;
    let user = null;
    user = await UserServices.findUserById(
      userId,
      '_id username email avatarURL fullName'
    );
    return res.status(200).json({ user });
  } catch (err) {
    console.log(err);
    return res.sendStatus(500);
  }
};
