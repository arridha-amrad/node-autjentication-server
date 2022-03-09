import { NextFunction, Request, Response } from 'express';
import argon2 from 'argon2';
import sendEmail from '../services/MailServices';
import {
  emailConfirmation,
  resetPasswordRequest,
} from '../templates/MailTemplates';
import * as JwtService from '../services/JwtServices';
import * as msg from '../templates/Message';
import * as Validator from '../validators/AuthValidator';
import {
  getRefreshTokenFromCookie,
  setCookieOptions,
} from '../utils/CookieHelpers';
import * as UserServices from '../services/UserServices';
import generateCode from '../utils/CodeGenerator';
import { IUserModel } from '../models/user/IUserModel';

export const registerHandler = async (
  req: Request,
  res: Response,
  _: NextFunction
) => {
  const { email, username, password } = req.body;
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
      strategy: 'default',
      requiredAuthAction: 'emailVerification',
    };
    const newUser = await UserServices.createUser(user);

    if (newUser) {
      const emailToken = await JwtService.createEmailLinkToken(email);

      // send the verificationCode via email
      await sendEmail(email, emailConfirmation(username, emailToken!));

      return res.status(201).json({ message: msg.registerSuccess(email) });
    }
    return res.status(400).json({ message: 'Create user failure' });
  } catch (err) {
    console.error(err);
    return res.status(500).send('Server Error');
  }
};

export const emailVerificationHandler = async (req: Request, res: Response) => {
  const { token } = req.params;

  const payload = await JwtService.verifyTokenLink(token);

  const user = await UserServices.findUserByUsernameOrEmail(payload.email);

  if (user?.isVerified) {
    return res.status(200).send('<p>Your email has been verified</p>');
  }

  if (user && user.requiredAuthAction === 'emailVerification') {
    await UserServices.findUserByIdAndUpdate(
      user.id!,
      {
        jwtVersion: await generateCode(),
        isActive: true,
        isLogin: true,
        isVerified: true,
        requiredAuthAction: 'none',
      },
      { new: true }
    );
    return res
      .status(200)
      .send(
        `<p>Verification Successfull</p> <a href=${process.env.CLIENT_ORIGIN}/login>Click here to login</a>`
      );
  } else {
    return res.status(200).send('<p>Verification failed</p>');
  }
};

export const loginHandler = async (req: Request, res: Response) => {
  const { identity, password } = req.body;
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
    const loginUser = {
      _id: user.id!,
      username: user.username,
      email: user.email,
      avatarURL: user.avatarURL,
      fullName: user.fullName,
    };

    return res
      .status(200)
      .cookie(process.env.COOKIE_REFRESH_TOKEN, refreshToken, setCookieOptions)
      .json({ user: loginUser, token: accessToken });
  } catch (err) {
    console.log(err);
    return res.status(500).send('Server Error');
  }
};

export const logoutHandler = async (_: Request, res: Response) => {
  res.clearCookie(process.env.COOKIE_ACC_TOKEN);
  res.clearCookie(process.env.COOKIE_REFRESH_TOKEN);
  return res.send('logout successfully');
};

export const refreshTokenHandler = async (req: Request, res: Response) => {
  const refreshToken = getRefreshTokenFromCookie(req);
  try {
    if (refreshToken) {
      const refreshTokenPayload = await JwtService.verifyRefreshToken(
        refreshToken
      );
      if (refreshTokenPayload) {
        const { jwtVersion, userId } = refreshTokenPayload;
        const user = await UserServices.findUserById(userId, 'jwtVersion');
        if (jwtVersion === user?.jwtVersion) {
          const newAccessToken = await JwtService.signAccessToken(userId);
          const newRefreshToken = await JwtService.signRefreshToken(user);
          return res
            .cookie(
              process.env.COOKIE_REFRESH_TOKEN,
              newRefreshToken,
              setCookieOptions
            )
            .json({ token: newAccessToken });
        }
      }
    }
    return res.sendStatus(403);
  } catch (err) {
    console.log(err);
    return res.sendStatus(500);
  }
};

export const forgotPasswordHandler = async (req: Request, res: Response) => {
  const { email } = req.body;
  const { errors, valid } = Validator.forgotPasswordValidator(email);
  if (!valid) {
    return res.status(400).json(errors);
  }
  try {
    // get user
    const user = await UserServices.findOne({ email });
    if (!user) {
      return res.sendStatus(404);
    }
    if (!user.isVerified) {
      return res.status(400).json({ message: msg.emailNotVerified });
    }
    user.requiredAuthAction = 'resetPassword';
    const token = await JwtService.createEmailLinkToken(email);
    if (token) {
      await sendEmail(email, resetPasswordRequest(user.username, token));
      return res.status(200).json({ message: msg.forgotPassword(email) });
    }
    return;
  } catch (err) {
    console.log('forgotPassword : ', err);
    return res.sendStatus(500);
  }
};

export const resetPasswordHandler = async (req: Request, res: Response) => {
  const { password } = req.body;
  const { token } = req.params;
  const { errors, valid } = Validator.resetPasswordValidator(password);
  if (!valid) {
    return res.status(400).json(errors);
  }
  try {
    const payload = await JwtService.verifyTokenLink(token);
    const user = await UserServices.findOne({ email: payload.email });
    if (user) {
      if (user.requiredAuthAction !== 'resetPassword') {
        return res.status(400).json({ message: 'Action is not granted' });
      }

      // update user's jwtVersion, password, requiredAuthAction
      await UserServices.findUserByIdAndUpdate(user.id, {
        jwtVersion: await generateCode(),
        requiredAuthAction: 'none',
        password: await argon2.hash(password),
      });

      // return
      return res.status(200).json({ message: msg.resetPassword });
    }
    return res.status(404).json({ message: 'User not found' });
  } catch (err) {
    console.log('confirmEmail errors : ', err);
    return res.sendStatus(500);
  }
};
