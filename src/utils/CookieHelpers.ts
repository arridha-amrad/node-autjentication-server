import { CookieOptions, Request } from 'express';

export const setCookieOptions: CookieOptions = {
  maxAge: 1000 * 60 * 60 * 24 * 365,
  httpOnly: true,
  sameSite: 'lax',
  secure: process.env.NODE_ENV === 'production',
};

export const getRefreshTokenFromCookie = (req: Request) => {
  return req.cookies.refreshToken as string | undefined;
};

export const getAuthTokenFromCookie = (req: Request) => {
  return req.cookies.authToken as string | undefined;
};
