import { Request, NextFunction, Response } from 'express';
import jwt from 'jsonwebtoken';
import {
  AccessTokenPayloadType,
  LinkPayloadType,
  RefreshTokenPayloadType,
} from '../interfacesAndTypes/JwtTypes';
import { HTTP_CODE } from '../enums/HTTP_CODE';
import Exception from '../exceptions/Exception';
import * as fs from 'fs';
import { IUserModel } from '../interfacesAndTypes/IUserModel';
import { decrypt } from '../utils/Encrypt';
import { getAuthTokenFromCookie } from '../utils/CookieHelpers';

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
  expiresIn: '7d',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
  algorithm: 'RS256',
};

const accessTokenVerifyOptions: jwt.VerifyOptions = {
  algorithms: ['RS256'],
  maxAge: '7d',
  issuer: 'node-authentication',
  audience: 'node-authentication-audience',
  subject: 'authentication',
};

export const signAccessToken = (
  user: IUserModel
): Promise<string | undefined> => {
  // console.log('public key : ', publicKey);
  return new Promise((resolve, reject) => {
    if (!user.id) {
      reject(new Error('signAccessToken error : userId not provided'));
    }
    jwt.sign(
      { userId: user.id, role: user.role },
      privateKey,
      accessTokenSignOptions,
      (err, token) => {
        if (err) {
          reject(err);
        }
        resolve(`Bearer ${token}`);
      }
    );
  });
};

// eslint-disable-next-line
export function verifyAccessToken(
  req: Request,
  _: Response,
  next: NextFunction
): void {
  const encryptedToken = getAuthTokenFromCookie(req);
  if (!encryptedToken) {
    return next(
      new Exception(HTTP_CODE.UNAUTHORIZED, 'You are not authorized')
    );
  }
  const token = decrypt(encryptedToken).split(' ')[1];
  if (!token) {
    console.log('verifyAccessToken error : Token not provided');
    return next(
      new Exception(HTTP_CODE.METHOD_NOT_ALLOWED, 'You are not authorized')
    );
  }
  jwt.verify(token, publicKey, accessTokenVerifyOptions, (err, payload) => {
    if (err) {
      return next(new Exception(HTTP_CODE.UNAUTHORIZED, err.message));
    }
    const result = payload as AccessTokenPayloadType;
    req.userId = result.userId;
    next();
  });
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
      (err, payload) => {
        if (err) {
          reject(new Error(`verifyRefreshToken error : ${err.message}`));
        }
        resolve(payload as RefreshTokenPayloadType);
      }
    );
  });
};
