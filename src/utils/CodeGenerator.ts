import { customAlphabet } from 'nanoid/async';

export default async () => {
  const verificationCodeGenerator = customAlphabet(
    // cspell:disable
    '1234567890qazwsxedcrfvtgbyhnujkilop',
    6
  );
  return verificationCodeGenerator();
};
