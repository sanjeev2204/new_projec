export interface IUser {
  _id: string;
  name: string;
  email: string;
  password: string;
  salt: string;

  street: string;
  city: string;
  street_line_2: string;
  zip: string;
  state: string;
}

export interface IUserInputDTO {
  name: string;
  email: string;
  password: string;

  street: string;
  city: string;
  street_line_2: string;
  zip: string;
  state: string;
}

export interface IUserUpdateDTO {
  street: string;
  city: string;
  street_line_2: string;
  zip: string;
  state: string;

  email: string;
  oldpassword: string;
  NewPassword: string;
  confirmNewPassword:string
}
