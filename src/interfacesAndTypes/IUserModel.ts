import { AuthenticationStrategy, RequiredAuthAction } from '../enums/UserEnum';

export interface IUserModel {
  id?: string;
  fullName?: string;
  username: string;
  strategy: AuthenticationStrategy;
  email: string;
  password?: string;
  requiredAuthAction: RequiredAuthAction;
  jwtVersion?: string;
  role?: string;
  avatarURL?: string;
  isActive?: boolean;
  isVerified?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}
