import { Request, Response } from 'express';
import { UserService } from '../services/user.service';
import { body, validationResult } from 'express-validator';
import session from 'express-session';
import { Title, InputValidation } from '../constants';
import asyncHandler from 'express-async-handler';

const userService = new UserService();

export const validateRegisterForm = [
  body('username')
    .trim()
    .isLength({ min: InputValidation.MIN_USERNAME_LENGTH, max: InputValidation.MAX_USERNAME_LENGTH })
    .withMessage("Invalid username length.")
    .escape(),
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage("Invalid email format."),
  body('password')
    .trim()
    .isLength({ min: InputValidation.MIN_PASSWORD_LENGTH })
    .withMessage("Password too short.")
    .escape(),
  body('confirm_password')
    .trim()
    .custom((value, { req }) => {
      if (value !== req.body.password) {
        throw new Error("Password mismatch.");
      }
      return true;
    }),
];

export const validateLoginForm = [
  body('usernameOrEmail')
    .trim()
    .custom((value) => {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      return emailRegex.test(value) || value.length >= InputValidation.MIN_USERNAME_LENGTH;
    })
    .withMessage('Invalid username or email format.'),
  body('password')
    .trim()
    .isLength({ min: InputValidation.MIN_PASSWORD_LENGTH })
    .withMessage('Password too short.')
    .escape(),
];

function validateSessionRole(req: Request) {
  return req.session.user ? req.session.user.role : null;
}

export const getRegister = asyncHandler(async (req: Request, res: Response) => {
  if (!validateSessionRole(req)) {
    res.render('auth/register', { title: Title.REGISTER });
  }
  else {
    res.redirect('/');
  }
});

export const postRegister = [
  ...validateRegisterForm,
  asyncHandler(async (req: Request, res: Response) => {
    const errors = validationResult(req);
    const { username, email, password } = req.body;
    if (!errors.isEmpty()) {
      res.render("auth/register", {
        title: Title.REGISTER,
        user: req.body,
        errors: errors.array(),
      });
    }
    else {
      const errors = [];
      const existUsernameUser = await userService.getUserByUsername(username);
      if (existUsernameUser) {
        errors.push({ msg: 'Username already exists.' });
      }
      const existEmailUser = await userService.getUserByEmail(email);
      if (existEmailUser) {
        errors.push({ msg: 'Email already exists.' });
      }
      if (errors.length > 0) {
        res.render("auth/register", {
          title: Title.REGISTER,
          user: req.body,
          errors,
        });
        return;
      }
      await userService.createUser(username, email, password);
      res.redirect('/login');
    }
  }),
];

export const getLogin = asyncHandler(async (req: Request, res: Response) => {
  if (!validateSessionRole(req)) {
    res.render('auth/login', { title: Title.LOGIN });
  }
  else {
    res.redirect('/');
  }
});

export const postLogin = [
  ...validateLoginForm,
  asyncHandler(async (req: Request, res: Response) => {
    const errors = validationResult(req);
    const { usernameOrEmail, password } = req.body;
    if (!errors.isEmpty()) {
      res.render("auth/login", {
        title: Title.LOGIN,
        user: req.body,
        errors: errors.array(),
      });
    }
    else {
      const user = await userService.getUserByUsernameOrEmail(usernameOrEmail);
      if (!user) return;
      const isMatch = await userService.verifyUser(user.username, password);
      if (!isMatch) return;
      req.session.user = {
        id: user.userId,
        email: user.email,
        username: user.username,
        role: user.role
      }
      res.redirect('/me');
    }
  }),
];
