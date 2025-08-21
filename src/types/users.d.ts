export type IUserProfileRoleType = "ADMIN" | "USER" | "MODERATOR";

export interface ILocalUserAttributes {
  id?: number;
  uid: string;
  email: string;
  password: string;
  role: IUserProfileRoleType;
  fullname: string;
  username?: string;
  avatar?: string;
  isActive: boolean;
  email_verified: boolean;
  last_login?: Date;
  created_at?: Date;
  updated_at?: Date;
}
