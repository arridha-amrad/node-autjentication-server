import { Request, NextFunction, Response } from 'express';
import jwt from 'jsonwebtoken';
import {
  AccessTokenPayloadType,
  LinkPayloadType,
  RefreshTokenPayloadType,
} from '../interfacesAndTypes/JwtTypes';
import * as fs from 'fs';
import { IUserModel } from '../models/user/IUserModel';

const publicKey = fs.readFileSync('keys/public.pem', 'utf-8');
const privateKey = fs.readFileSync('keys/private.pem', 'utf-8');

const emailLinkSignOptions: jwt.SignOptions = {
  expiresIn: '7d',
  algorithm: 'RS256',
};

const emailLinkVerifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '7d',
};

export const createEmailLinkToken = (
  email: string
): Promise<string | undefined> => {
  return new Promise((resolve, reject) => {
    if (!email) {
      reject(new Error('createEmailLinkToken error : email not provided'));
    }
    jwt.sign({ email }, privateKey, emailLinkSignOptions, (err, token) => {
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
    jwt.verify(token, publicKey, emailLinkVerifyOptions, (err, payload) => {
      if (err) {
        reject(new Error(`verifyEmailTokenLink error : ${err.message}`));
      }
      resolve(payload as LinkPayloadType);
    });
  });
};

//* ACCESS TOKEN
const accessTokenSignOptions: jwt.SignOptions = {
  expiresIn: '20s',
  algorithm: 'RS256',
};

const accessTokenVerifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '20s',
};

export const signAccessToken = (
  userId: string
): Promise<string | undefined> => {
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
) {
  const bearerToken = req.headers['authorization'] as string;
  if (!bearerToken) {
    return res.status(401).send('no token');
  }
  const token = bearerToken.split('Bearer ')[1];

  return jwt.verify(
    token,
    publicKey,
    accessTokenVerifyOptions,
    (err, payload) => {
      if (err && err.message === 'jwt expired') {
        return res.status(401).send('token expired');
      }
      const verifyTokenPayload = payload as AccessTokenPayloadType | undefined;

      if (verifyTokenPayload) {
        req.userId = verifyTokenPayload.userId;
        return next();
      }
    }
  );
}

//* REFRESH TOKEN
const refreshTokenSignOptions: jwt.SignOptions = {
  expiresIn: '1y',
  algorithm: 'RS256',
};

const refreshTokenVerifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '1y',
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
    const token = oldRefreshToken.split(' ')[1];
    jwt.verify(token, publicKey, refreshTokenVerifyOptions, (err, payload) => {
      if (err) {
        reject(new Error(`verifyRefreshToken error : ${err.message}`));
      }
      resolve(payload as RefreshTokenPayloadType);
    });
  });
};
