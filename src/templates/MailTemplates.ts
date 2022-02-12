import { IMailContent } from '../interfacesAndTypes/MailInterfaces';

export const emailConfirmation = (
  username: string,
  token: string
): IMailContent => ({
  subject: `${process.env.APP_NAME} - Email confirmation`,
  text: `Please use this link to confirm your email`,
  html: `<p>Hello ${username}</p><p>Please use the following link to reset your password:</p> <p>${process.env.SERVER_ORIGIN}/api/auth/email-verification/${token}</p> <p>If you didn’t ask to reset your password, you can ignore this email.
    </p> <p>Thanks</p>`,
});

export const resetPasswordRequest = (
  username: string,
  token: string
): IMailContent => ({
  subject: `${process.env.APP_NAME} - Password Reset Instructions`,
  text: `Please use the following link to reset your password: ${process.env.CLIENT_ORIGIN}/reset-password/${token}`,
  html: `<p>Hello ${username}</p><p>Please use the following link to reset your password:</p> <p>${process.env.CLIENT_ORIGIN}/reset-password/${token}</p> <p>If you didn’t ask to reset your password, you can ignore this email.
    </p> <p>Thanks</p>`,
});
