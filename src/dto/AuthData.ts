import { IUserModel } from '../interfacesAndTypes/IUserModel';

export type LoginRequest = Pick<IUserModel, 'password'> & {
  identity: string;
};

export type RegisterRequest = Pick<
  IUserModel,
  'username' | 'email' | 'password'
>;

export type LoginResponse = Pick<IUserModel, 'email' | 'username' | 'id'>;

export type FetchedUserResponse = Pick<
  IUserModel,
  'username' | 'email' | 'createdAt'
>;

export type LoginUserData = Pick<
  IUserModel,
  'username' | 'email' | 'fullName' | 'avatarURL'
> & { _id: string };
