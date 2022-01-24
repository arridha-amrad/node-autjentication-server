import { CookieOptions, Request } from 'express';

export const setCookieOptions = (): CookieOptions => {
  const date = new Date();
  date.setTime(date.getTime() + 5 * 24 * 60 * 60 * 1000);
  return {
    httpOnly: true,
    sameSite: 'lax',
    expires: new Date(date),
    secure: process.env.NODE_ENV === 'production',
  };
};

export const getUserIdFromCookie = (req: Request) => {
  return req.cookies.cid as string;
};

export const getAuthTokenFromCookie = (req: Request) => {
  return req.cookies.authCookie as string;
};
