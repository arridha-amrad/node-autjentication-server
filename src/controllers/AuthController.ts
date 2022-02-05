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
import { LoginRequest, RegisterRequest, SessionUser } from '../dto/AuthData';
import VerificationCodeModel from '../models/VerificationCodeModel';
import {
  getRefreshTokenFromCookie,
  setCookieOptions,
} from '../utils/CookieHelpers';
import * as UserServices from '../services/UserServices';
import { IUserModel } from '../interfacesAndTypes/IUserModel';
import { getUserFromSession, setUserToSession } from '../utils/SessionHelper';
import { decrypt, encrypt } from '../utils/Encrypt';
import codeGenerator from '../utils/CodeGenerator';

export const registerHandler = async (
  req: Request,
  res: Response,
  _: NextFunction
) => {
  const { email, username, password }: RegisterRequest = req.body;
  const { errors, valid } = Validator.registerValidator({
    email,
    password,
    username,
  });
  if (!valid) {
    return res.status(400).json(errors);
  }
  try {
    // email and username must be unique
    const isEmailRegistered = await UserServices.findOne({ email });
    if (isEmailRegistered) {
      return res.status(400).json({ message: 'Email has been registered' });
    }
    const isUsernameRegistered = await UserServices.findOne({ username });
    if (isUsernameRegistered) {
      return res.status(400).json({ message: 'Username has been registered' });
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
    if (newUser) {
      // generate code for email verification & save in DB
      const verificationCode = await codeGenerator();
      const newVerificationCode = new VerificationCodeModel({
        code: verificationCode,
        owner: newUser.id,
      });
      await newVerificationCode.save();

      // set userId in session
      req.session.registerId = newUser.id;

      // send the verificationCode via email
      await sendEmail(email, emailConfirmation(username, verificationCode));

      // create cookie to hold userId
      return res.status(201).json({ message: msg.registerSuccess(email) });
    }
    return res.status(400).json({ message: 'Create user failure' });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server Error');
  }
};

export const emailVerificationHandler = async (req: Request, res: Response) => {
  const { verificationCode } = req.body;
  if (verificationCode.trim() === '') {
    return res.status(400).json({ message: 'Invalid code' });
  }
  try {
    // get userId from cookie
    const userId = req.session.registerId;

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
          jwtVersion: await codeGenerator(),
          isActive: true,
          isLogin: true,
          isVerified: true,
          requiredAuthAction: RequiredAuthAction.none,
        },
        { new: true }
      );

      // create accessToken and refreshToken
      if (user) {
        const accessToken = await JwtService.signAccessToken(user.id!);
        const refreshToken = await JwtService.signRefreshToken(user!);
        // return userData with cookie
        const loginUser: SessionUser = {
          _id: user.id!,
          username: user.username,
          email: user.email,
          fullName: user.fullName,
          avatarURL: user.avatarURL,
          jwtVersion: user.jwtVersion,
          role: user.role,
        };

        // eslint-disable-next-line no-unused-vars
        const { jwtVersion, role, ...rest } = loginUser;

        // set login user into session
        req.session.user = loginUser;

        return res
          .status(200)
          .cookie(process.env.COOKIE_ACC_TOKEN, accessToken, setCookieOptions())
          .cookie(
            process.env.COOKIE_REFRESH_TOKEN,
            refreshToken,
            setCookieOptions()
          )
          .json({ user: rest });
      }
    }
    return res.status(400).json({ message: 'Invalid request' });
  } catch (err) {
    console.log('confirmEmail errors : ', err);
    return res.status(500).send('Server Error');
  }
};

export const loginHandler = async (req: Request, res: Response) => {
  const { identity, password }: LoginRequest = req.body;
  const { valid, errors } = Validator.loginValidator({
    identity,
    password,
  });
  if (!valid) {
    return res.status(400).json(errors);
  }
  try {
    // get user from DB
    const user = await UserServices.findUserByUsernameOrEmail(identity);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    if (!user.isVerified) {
      return res.status(400).json({ message: msg.emailNotVerified });
    }

    // compare the password
    const isMatch = await argon2.verify(user.password!, password!);
    if (!isMatch) {
      return res.status(400).json({ message: 'Password not match' });
    }

    // create accessToken and refreshToken
    const accessToken = await JwtService.signAccessToken(user.id!);
    const refreshToken = await JwtService.signRefreshToken(user);
    const loginUser: SessionUser = {
      _id: user.id!,
      username: user.username,
      email: user.email,
      avatarURL: user.avatarURL,
      fullName: user.fullName,
      jwtVersion: user.jwtVersion,
      role: user.role,
    };

    // setUser into session
    setUserToSession(loginUser, req);

    // return with session, cookieAuthToken, cookieRefreshToken, userData
    // eslint-disable-next-line no-unused-vars
    const { jwtVersion, role, ...rest } = loginUser;

    return res
      .status(200)
      .cookie(process.env.COOKIE_ACC_TOKEN, accessToken, setCookieOptions())
      .cookie(
        process.env.COOKIE_REFRESH_TOKEN,
        refreshToken,
        setCookieOptions()
      )
      .json({ user: rest });
  } catch (err) {
    console.log(err);
    return res.status(500).send('Server Error');
  }
};

export const logoutHandler = async (req: Request, res: Response) => {
  try {
    // verify the token first
    const userId = req.session.user?._id;
    if (userId) {
      // delete user's cookie
      res.clearCookie(process.env.COOKIE_ACC_TOKEN);
      res.clearCookie(process.env.COOKIE_REFRESH_TOKEN);
      req.session.destroy((err) => res.send(`err to destroy session : ${err}`));
      res.send('logout successfully');
    }
  } catch (error) {
    console.log(error);
    res.status(500).send('Server Error');
  }
};

export const refreshTokenHandler = async (
  req: Request,
  res: Response,
  next: NextFunction
) => {
  try {
    // get userId from cookie
    const userId = getUserFromSession(req);
    if (!userId) {
      return next(
        new Exception(
          HTTP_CODE.METHOD_NOT_ALLOWED,
          'you must login to continue'
        )
      );
    }

    // get userData from refreshToken and compare to currentUser data in DB
    const bearerRefreshToken = getRefreshTokenFromCookie(req);
    const token = bearerRefreshToken!.split(' ')[1];
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
        const newAccessToken = await JwtService.signAccessToken(user.id!);
        const newRefreshToken = await JwtService.signRefreshToken(user);

        if (newAccessToken && newRefreshToken) {
          // update cookie
          return res
            .status(200)
            .cookie(
              process.env.COOKIE_ACC_TOKEN,
              newAccessToken,
              setCookieOptions()
            )
            .cookie(
              process.env.COOKIE_REFRESH_TOKEN,
              newRefreshToken,
              setCookieOptions()
            )
            .send('cookie renew');
        }
      }
    }
  } catch (err) {
    console.log(err);
    return res.status(500).send('Server Error');
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
    return res.status(500).send('Server Error');
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
    return res.status(500).send('Server Error');
  }
};
