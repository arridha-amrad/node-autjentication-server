import { Request, NextFunction, Response } from 'express';
import jwt from 'jsonwebtoken';
import {
  LinkPayloadType,
  RefreshTokenPayloadType,
} from '../interfacesAndTypes/JwtTypes';
import * as fs from 'fs';
import { IUserModel } from '../interfacesAndTypes/IUserModel';
import {
  getAuthTokenFromCookie,
  setCookieOptions,
} from '../utils/CookieHelpers';

const publicKey = fs.readFileSync('keys/public.pem', 'utf-8');
const privateKey = fs.readFileSync('keys/private.pem', 'utf-8');

const signOptions: jwt.SignOptions = {
  expiresIn: '7d',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
  algorithm: 'RS256',
};

const verifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '7d',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
};

export const createEmailLinkToken = (
  email: string
): Promise<string | undefined> => {
  return new Promise((resolve, reject) => {
    if (!email) {
      reject(new Error('createEmailLinkToken error : email not provided'));
    }
    jwt.sign({ email }, privateKey, signOptions, (err, token) => {
      if (err) {
        reject(new Error(`createEmailLinkToken error : ${err.message}`));
      }
      resolve(token);
    });
  });
};

export const verifyTokenLink = (token: string): Promise<LinkPayloadType> => {
  return new Promise((resolve, reject) => {
    if (!token) {
      reject(new Error('verifyEmailTokenLink error : token not provided'));
    }
    jwt.verify(token, publicKey, verifyOptions, (err, payload) => {
      if (err) {
        reject(new Error(`verifyEmailTokenLink error : ${err.message}`));
      }
      resolve(payload as LinkPayloadType);
    });
  });
};

//* ACCESS TOKEN
const accessTokenSignOptions: jwt.SignOptions = {
  expiresIn: '7s',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
  algorithm: 'RS256',
};

const accessTokenVerifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '7s',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
};

export const signAccessToken = (
  userId: string
): Promise<string | undefined> => {
  // console.log('public key : ', publicKey);
  return new Promise((resolve, reject) => {
    if (!userId) {
      reject(new Error('signAccessToken error : userId not provided'));
    }

    jwt.sign({ userId }, privateKey, accessTokenSignOptions, (err, token) => {
      if (err) {
        reject(err);
      }
      resolve(`Bearer ${token}`);
    });
  });
};

// eslint-disable-next-line
export function verifyAccessToken(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const token = getAuthTokenFromCookie(req)?.split(' ')[1];
  if (token) {
    jwt.verify(
      token,
      publicKey,
      accessTokenVerifyOptions,
      (err, payload: any) => {
        if (payload) {
          req.userId = payload as string;
        }
        console.log('err : ', err?.message);
        if (req.session.user) {
          req.userId = req.session.user?._id!;
          signAccessToken(req.session.user._id).then((accToken) => {
            res.cookie(
              process.env.COOKIE_ACC_TOKEN,
              accToken,
              setCookieOptions()
            );
            console.log('cookie renew');
          });
        }
      }
    );
  }

  next();
}

//* REFRESH TOKEN
const refreshTokenSignOptions: jwt.SignOptions = {
  expiresIn: '1y',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
  algorithm: 'RS256',
};

const refreshTokenVerifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '1y',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
};
export const signRefreshToken = (
  user: IUserModel
): Promise<string | undefined> => {
  return new Promise((resolve, reject) => {
    if (!user) {
      reject(new Error('signRefreshToken error : userId not provided'));
    }
    if (!user.jwtVersion) {
      reject(new Error('signRefreshToken error : jwtVersion not provided'));
    }
    jwt.sign(
      { userId: user.id, jwtVersion: user.jwtVersion },
      privateKey,
      refreshTokenSignOptions,
      (err, token) => {
        if (err) {
          reject(new Error(`signRefreshToken error : ${err.message}`));
        } else {
          resolve(`Bearer ${token}`);
        }
      }
    );
  });
};

export const verifyRefreshToken = (
  oldRefreshToken: string
): Promise<RefreshTokenPayloadType | undefined> => {
  return new Promise((resolve, reject) => {
    if (!oldRefreshToken) {
      reject(
        new Error('verifyRefreshToken error : old refresh token not provided')
      );
    }
    jwt.verify(
      oldRefreshToken,
      publicKey,
      refreshTokenVerifyOptions,
      (err, payload: any) => {
        if (err) {
          reject(new Error(`verifyRefreshToken error : ${err.message}`));
        }
        resolve(payload);
      }
    );
  });
};
