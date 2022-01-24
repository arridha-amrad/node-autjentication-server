import { NextFunction, Request, Response } from 'express';
import { AuthenticationStrategy, RequiredAuthAction } from '../enums/UserEnum';
import { v4 } from 'uuid';
import argon2 from 'argon2';
import sendEmail from '../services/MailServices';
import {
  emailConfirmation,
  resetPasswordRequest,
} from '../templates/MailTemplates';
import * as JwtService from '../services/JwtServices';
import * as msg from '../templates/NotificationTemplates';
import { HTTP_CODE } from '../enums/HTTP_CODE';
import * as Validator from '../validators/AuthValidator';
import { BadRequestException } from '../exceptions/BadRequestException';
import Exception from '../exceptions/Exception';
import ServerErrorException from '../exceptions/ServerErrorException';
import * as RedisServices from '../services/RedisServices';
import { decrypt, encrypt } from '../utils/Encrypt';
import { LoginRequest, LoginUserData, RegisterRequest } from '../dto/AuthData';
import { customAlphabet } from 'nanoid/async';
import VerificationCodeModel from '../models/VerificationCodeModel';
import {
  getAuthTokenFromCookie,
  getUserIdFromCookie,
  setCookieOptions,
} from '../utils/CookieHelpers';
import * as UserServices from '../services/UserServices';
import { IUserModel } from '../interfacesAndTypes/IUserModel';

export const checkIsAuthenticated = async (
  req: Request,
  res: Response
): Promise<void> => {
  const userId = getUserIdFromCookie(req);
  const LOGIN_COOKIE = getAuthTokenFromCookie(req);
  if (userId && LOGIN_COOKIE) {
    const user = await UserServices.findUserById(userId);
    if (user) {
      res.send('login');
    }
  } else {
    res.send('not login');
  }
};

export const registerHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { email, username, password }: RegisterRequest = req.body;
  const { errors, valid } = Validator.registerValidator({
    email,
    password,
    username,
  });
  if (!valid) next(new BadRequestException(errors));
  try {
    // email and username must be unique
    const isEmailRegistered = await UserServices.findOne({ email });
    if (isEmailRegistered) {
      return res
        .status(HTTP_CODE.FORBIDDEN)
        .json({ message: 'Email has been registered' });
    }
    const isUsernameRegistered = await UserServices.findOne({ username });
    if (isUsernameRegistered) {
      return res
        .status(HTTP_CODE.FORBIDDEN)
        .json({ message: 'Username has been registered' });
    }

    // hash the input password & create new user
    const hashedPassword = await argon2.hash(password!);
    const user: IUserModel = {
      email,
      username,
      password: hashedPassword,
      strategy: AuthenticationStrategy.default,
      requiredAuthAction: RequiredAuthAction.emailVerification,
    };
    const newUser = await UserServices.createUser(user);

    // generate code for email verification & save in DB
    const verificationCodeGenerator = customAlphabet(
      // cspell:disable
      '1234567890qazwsxedcrfvtgbyhnujkilop',
      6
    );
    const verificationCode = await verificationCodeGenerator();
    const newVerificationCode = new VerificationCodeModel({
      code: verificationCode,
      owner: newUser.id,
    });
    await newVerificationCode.save();

    // send the verificationCode via email
    await sendEmail(email, emailConfirmation(username, verificationCode));

    // create cookie to hold userId
    return res
      .status(201)
      .cookie(process.env.COOKIE_ID, newUser.id, setCookieOptions())
      .json({ message: msg.registerSuccess(email) });
  } catch (err) {
    console.error(err);
    return next(new ServerErrorException());
  }
};

export const emailVerificationHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { verificationCode } = req.body;
  if (verificationCode.trim() === '') {
    return next(new Exception(HTTP_CODE.BAD_REQUEST, 'invalid code'));
  }
  try {
    // get userId from cookie
    const userId = getUserIdFromCookie(req);

    // get user's code and update user data
    const code = await VerificationCodeModel.findOne({
      owner: userId,
    }).populate('owner', '-password');
    if (userId && code && !code.isComplete && code.code === verificationCode) {
      code.isComplete = true;
      await code.save();
      const user = await UserServices.findUserByIdAndUpdate(
        userId,
        {
          jwtVersion: v4(),
          isActive: true,
          isLogin: true,
          isVerified: true,
          requiredAuthAction: RequiredAuthAction.none,
        },
        { new: true }
      );

      // create accessToken and refreshToken
      const accessToken = await JwtService.signAccessToken(user!);
      const refreshToken = await JwtService.signRefreshToken(user!);
      const encryptedAccessToken = encrypt(accessToken!);
      const encryptedRefreshToken = encrypt(refreshToken!);

      // store refreshToken in redis
      await RedisServices.setRefreshTokenInRedis(userId, encryptedRefreshToken);

      if (user) {
        // return userData with cookie
        const loginUser: LoginUserData = {
          _id: user.id!,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          avatarURL: user.avatarURL,
        };
        return res
          .status(200)
          .cookie(
            process.env.COOKIE_NAME,
            encryptedAccessToken,
            setCookieOptions()
          )
          .json({ user: loginUser });
      }
    } else {
      return next(
        new Exception(
          HTTP_CODE.METHOD_NOT_ALLOWED,
          'Action is stopped by server'
        )
      );
    }
  } catch (err) {
    console.log('confirmEmail errors : ', err);
    return next(new ServerErrorException());
  }
};

export const loginHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { identity, password }: LoginRequest = req.body;
  const { valid, errors } = Validator.loginValidator({
    identity,
    password,
  });
  if (!valid) {
    return next(new BadRequestException(errors));
  }
  try {
    // get user from DB
    const user = await UserServices.findUserByUsernameOrEmail(identity);
    if (!user) {
      return next(new Exception(HTTP_CODE.NOT_FOUND, 'user not found'));
    }
    if (!user.isVerified) {
      return next(new Exception(HTTP_CODE.FORBIDDEN, msg.emailNotVerified));
    }

    // compare the password
    const isMatch = await argon2.verify(user.password!, password!);
    if (!isMatch) {
      return next(new Exception(HTTP_CODE.FORBIDDEN, msg.invalidPassword));
    }

    // create accessToken and refreshToken
    const accessToken = await JwtService.signAccessToken(user);
    const refreshToken = await JwtService.signRefreshToken(user);
    if (accessToken && refreshToken) {
      const encryptedAccessToken = encrypt(accessToken);
      const encryptedRefreshToken = encrypt(refreshToken);

      // store refreshToken to redis
      await RedisServices.setRefreshTokenInRedis(
        user.id!,
        encryptedRefreshToken
      );

      const loginUser: LoginUserData = {
        _id: user.id!,
        username: user.username,
        email: user.email,
        avatarURL: user.avatarURL,
        fullName: user.fullName,
      };

      // return with cookieId, cookieAuthToken, userData
      return res
        .status(200)
        .cookie(process.env.COOKIE_ID, user.id, setCookieOptions())
        .cookie(
          process.env.COOKIE_NAME,
          encryptedAccessToken,
          setCookieOptions()
        )
        .json({ user: loginUser });
    }
  } catch (err) {
    console.log(err);
    return next(new ServerErrorException());
  }
};

export const logoutHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    // verify the token first
    const userId = getUserIdFromCookie(req);
    if (userId) {
      // delete user's cookie
      res.clearCookie(process.env.COOKIE_NAME);
      res.clearCookie(process.env.COOKIE_ID);
      res.send('logout successfully');
    }
  } catch (error) {
    console.log(error);
    return next(new ServerErrorException());
  }
};

export const refreshTokenHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // get userId from cookie
    const userId = getUserIdFromCookie(req);
    if (!userId) {
      return next(
        new Exception(
          HTTP_CODE.METHOD_NOT_ALLOWED,
          'you must login to continue'
        )
      );
    }

    // get userData from refreshToken and compare to currentUser data in DB
    const encryptedRefreshToken = await RedisServices.getRefreshTokenFromRedis(
      userId
    );
    const bearerRefreshToken = decrypt(encryptedRefreshToken ?? '');
    const token = bearerRefreshToken.split(' ')[1];
    const payload = await JwtService.verifyRefreshToken(token);
    if (payload) {
      const user = await UserServices.findUserById(payload.userId);
      if (user) {
        if (user.jwtVersion !== payload.jwtVersion) {
          return next(
            new Exception(HTTP_CODE.METHOD_NOT_ALLOWED, 'expired jwt version')
          );
        }

        // create new accessToken and refreshToken
        const newAccessToken = await JwtService.signAccessToken(user);
        const newRefreshToken = await JwtService.signRefreshToken(user);

        if (newAccessToken && newRefreshToken) {
          const newEncryptedAccessToken = encrypt(newAccessToken);
          const newEncryptedRefreshToken = encrypt(newRefreshToken);
          await RedisServices.setRefreshTokenInRedis(
            userId,
            newEncryptedRefreshToken
          );

          // update cookie
          return res
            .status(200)
            .cookie(process.env.COOKIE_ID, userId, setCookieOptions())
            .cookie(
              process.env.COOKIE_NAME,
              newEncryptedAccessToken,
              setCookieOptions()
            )
            .send('cookie renew');
        }
      }
    }
  } catch (err) {
    console.log(err);
    return next(new ServerErrorException());
  }
};

export const forgotPasswordHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { email } = req.body;
  const { errors, valid } = Validator.forgotPasswordValidator(email);
  if (!valid) {
    return next(new BadRequestException(errors));
  }
  try {
    // get user
    const user = await UserServices.findOne({ email });
    if (!user) {
      return next(new Exception(HTTP_CODE.NOT_FOUND, msg.userNotFound));
    }
    if (!user.isVerified) {
      return next(new Exception(HTTP_CODE.FORBIDDEN, msg.emailNotVerified));
    }
    user.requiredAuthAction = RequiredAuthAction.resetPassword;
    await user.save();
    const token = await JwtService.createEmailLinkToken(email);
    if (token) {
      const encryptedToken = encrypt(token).replace(/\//g, '_');
      await sendEmail(
        email,
        resetPasswordRequest(user.username, encryptedToken)
      );
      return res.status(200).json({ message: msg.forgotPassword(email) });
    }
  } catch (err) {
    console.log('forgotPassword : ', err);
    return next(new ServerErrorException());
  }
};

export const resetPasswordHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  const { password } = req.body;
  const { encryptedLinkToken } = req.params;
  const { errors, valid } = Validator.resetPasswordValidator(password);
  if (!valid) {
    return next(new BadRequestException(errors));
  }
  try {
    const token = decrypt(encryptedLinkToken.replace(/_/g, '/'));
    const payload = await JwtService.verifyTokenLink(token);
    const user = await UserServices.findOne({ email: payload.email });
    if (user) {
      if (user.requiredAuthAction !== RequiredAuthAction.resetPassword) {
        return next(new Exception(HTTP_CODE.BAD_REQUEST, 'Action not granted'));
      }

      // update user's jwtVersion, password, requiredAuthAction
      await UserServices.findUserByIdAndUpdate(user.id, {
        jwtVersion: v4(),
        requiredAuthAction: RequiredAuthAction.none,
        password: await argon2.hash(password),
      });

      // return
      return res.status(200).json({ message: msg.resetPassword });
    }
  } catch (err) {
    console.log('confirmEmail errors : ', err);
    return next(new ServerErrorException());
  }
};
