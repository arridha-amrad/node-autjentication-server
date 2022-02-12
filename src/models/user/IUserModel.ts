export interface IUserModel {
  id?: string;
  fullName?: string;
  username: string;
  strategy: 'default' | 'google' | 'facebook';
  email: string;
  password?: string;
  requiredAuthAction: 'none' | 'emailVerification' | 'resetPassword';
  jwtVersion?: string;
  role?: string;
  avatarURL?: string;
  isActive?: boolean;
  isVerified?: boolean;
  createdAt?: Date;
  updatedAt?: Date;
}
