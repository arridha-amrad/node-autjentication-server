import { Request, Response } from 'express';

export default async function (req: Request, res: Response) {
  console.log('user', req.user);
  console.log('session : ', req.session);
  req.session.test = 'test';

  res.redirect(`${process.env.CLIENT_ORIGIN}/login`);
}
