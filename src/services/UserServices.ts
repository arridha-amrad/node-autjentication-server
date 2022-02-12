import { FilterQuery, QueryOptions, UpdateQuery } from 'mongoose';
import { IUserModel } from '../models/user/IUserModel';
import UserModel from '../models/user/UserModel';

export const save = async (user: IUserModel): Promise<IUserModel> => {
  const newUser = new UserModel(user);
  return newUser.save();
};

export const createUser = async (newUser: IUserModel) => {
  return UserModel.create(newUser);
};

export const findUserByUsernameOrEmail = async (
  usernameOrEmail: string
): Promise<IUserModel | null> => {
  return UserModel.findOne(
    usernameOrEmail.includes('@')
      ? { email: usernameOrEmail }
      : { username: usernameOrEmail }
  );
};

export const findUserById = async (
  userId: string,
  selects?: string
): Promise<IUserModel | null> => {
  return UserModel.findById(userId).select(selects);
};

export const findUserByIdAndUpdate = async (
  id: string,
  update: UpdateQuery<IUserModel>,
  options?: QueryOptions | null
): Promise<IUserModel | null> => {
  return UserModel.findByIdAndUpdate(id, update, options);
};

export const findOne = async (query: FilterQuery<IUserModel>) => {
  return UserModel.findOne(query);
};
