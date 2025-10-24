/* eslint-disable no-console */
import { User } from '../models/user.module.js';
import { userService } from '../services/user.service.js';
import { jwtService } from '../services/jwt.service.js';
import { ApiError } from '../exeptions/api.error.js';
import bcrypt from 'bcrypt';
import { tokenService } from '../services/token.service.js';
import { v4 as uuidv4 } from 'uuid';
import { emailService } from '../services/email.service.js';

function validateEmail(value) {
  if (!value) {
    return 'Email is required';
  }

  const emailPattern = /^[\w.+-]+@([\w-]+\.){1,3}[\w-]{2,}$/;

  if (!emailPattern.test(value)) {
    return 'Email is not valid';
  }
}

function validatePassword(value) {
  if (!value) {
    return 'Password is required';
  }

  if (value.length < 6) {
    return 'At least 6 characters';
  }
}

function validateName(value) {
  if (!value) {
    return 'Name is required';
  }

  if (value.length < 2) {
    return 'At least 2 characters';
  }
}

const generateTokens = async (user) => {
  const normalizedUser = userService.normalize(user);
  const accessToken = jwtService.sign(normalizedUser);
  const refreshToken = jwtService.signRefresh(normalizedUser);

  await tokenService.save(user.id, refreshToken);

  return { normalizedUser, accessToken, refreshToken };
};

export const register = async (req, res, next) => {
  try {
    const { name, email, password } = req.body;
    const errors = {
      email: validateEmail(email),
      password: validatePassword(password),
      name: validateName(name),
    };

    if (errors.email || errors.password || errors.name) {
      throw ApiError.badRequest('Validation failed', errors);
    }

    const candidate = await User.findOne({ where: { email } });

    if (candidate) {
      throw ApiError.badRequest(`User with email ${email} already exists`);
    }

    const hashPassword = await bcrypt.hash(password, 10);
    const activationToken = uuidv4();
    const user = await User.create({
      name,
      email,
      password: hashPassword,
      activationToken,
    });

    await emailService.sendActivationEmail(email, activationToken);

    const { normalizedUser, accessToken, refreshToken } =
      await generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    return res.json({
      message: 'Registration successful. Check your email to activate account.',
      user: normalizedUser,
      accessToken,
    });
  } catch (e) {
    console.error('updateProfile caught error:', e);

    if (!res.headersSent) {
      next(e);
    }
  }
};

export const activate = async (req, res, next) => {
  try {
    const { activationToken } = req.params;
    const user = await User.findOne({ where: { activationToken } });

    if (!user) {
      return res.status(404).json({ message: 'Wrong activation link' });
    }

    user.activationToken = null;
    await user.save();

    const { normalizedUser, accessToken, refreshToken } =
      await generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    return res.json({ accessToken, refreshToken, user: normalizedUser });
  } catch (e) {
    if (!res.headersSent) {
      next(e);
    }
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const user = await userService.findByEmail(email);

    if (!user) {
      throw ApiError.badRequest('No such user');
    }

    const isValid = await bcrypt.compare(password, user.password);

    if (!isValid) {
      throw ApiError.badRequest('Wrong password');
    }

    const { normalizedUser, accessToken, refreshToken } =
      await generateTokens(user);

    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      maxAge: 30 * 24 * 60 * 60 * 1000,
      sameSite: 'lax',
      secure: false,
    });

    return res.json({ user: normalizedUser, accessToken });
  } catch (e) {
    if (!res.headersSent) {
      next(e);
    }
  }
};

export const refresh = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(401).json({ message: 'No refresh token' });
    }

    const tokenFromDb = await tokenService.getByToken(refreshToken);

    if (!tokenFromDb) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const userData = jwtService.verifyRefresh(refreshToken);

    if (!userData) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    const user = await userService.findByEmail(userData.email);

    if (!user) {
      return res.status(401).json({ message: 'User not found' });
    }

    const normalizedUser = userService.normalize(user);
    const accessToken = jwtService.sign(normalizedUser);

    return res.json({ user: normalizedUser, accessToken, refreshToken });
  } catch (e) {
    if (!res.headersSent) {
      next(e);
    }
  }
};

export const logout = async (req, res, next) => {
  try {
    const { refreshToken } = req.cookies;

    if (!refreshToken) {
      return res.status(401).json({ message: 'No refresh token' });
    }

    const userData = jwtService.verifyRefresh(refreshToken);

    if (!userData) {
      return res.status(401).json({ message: 'Invalid refresh token' });
    }

    await tokenService.remove(userData.id);
    res.clearCookie('refreshToken');

    return res.sendStatus(204);
  } catch (e) {
    if (!res.headersSent) {
      next(e);
    }
  }
};

export const requestReset = async (req, res, next) => {
  try {
    const { email } = req.body;
    const errors = { email: validateEmail(email) };

    if (errors.email) {
      throw ApiError.badRequest('Bad request', errors);
    }

    const user = await userService.findByEmail(email);

    if (!user) {
      return res.json({
        message: 'If that email exists, you’ll get a reset link soon.',
      });
    }

    const resetToken = uuidv4();

    user.resetToken = resetToken;
    await user.save();
    await emailService.sendResetPasswordEmail(email, resetToken);

    return res.json({ message: 'Password reset email sent' });
  } catch (e) {
    if (!res.headersSent) {
      next(e);
    }
  }
};

export const resetPassword = async (req, res, next) => {
  try {
    const { resetToken } = req.params;
    const { password } = req.body;
    const user = await User.findOne({ where: { resetToken } });

    if (!user) {
      throw ApiError.badRequest('Invalid or expired reset token');
    }

    user.password = await bcrypt.hash(password, 10);
    user.resetToken = null;
    await user.save();
    await tokenService.remove(user.id);
    res.clearCookie('refreshToken');

    return res.json({ message: 'Password has been reset successfully' });
  } catch (e) {
    if (!res.headersSent) {
      next(e);
    }
  }
};

export async function updateProfile(req, res, next) {
  try {
    const userId = req.user.id;
    const {
      name,
      oldPassword,
      newPassword,
      confirmPassword,
      password,
      email,
      confirmEmail,
    } = req.body;

    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (name) {
      user.name = name;
    }

    if (oldPassword && newPassword && confirmPassword) {
      if (newPassword !== confirmPassword) {
        return res.status(400).json({ message: 'Passwords do not match' });
      }

      const isPasswordValid = await bcrypt.compare(oldPassword, user.password);

      if (!isPasswordValid) {
        return res.status(401).json({ message: 'Invalid current password' });
      }

      const hashed = await bcrypt.hash(newPassword, 10);

      user.password = hashed;
    }

    let accessToken = null;
    let sendEmails = false;
    let oldEmail = null;

    if (email && confirmEmail && password) {
      if (email !== confirmEmail) {
        return res.status(400).json({ message: 'Emails do not match' });
      }

      const isPasswordValidEmail = await bcrypt.compare(
        password,
        user.password,
      );

      if (!isPasswordValidEmail) {
        return res.status(401).json({ message: 'Invalid password' });
      }

      oldEmail = user.email;
      user.email = email;
      sendEmails = true;
    }

    await user.save();

    accessToken = jwtService.sign(
      { id: user.id, email: user.email },
      process.env.JWT_KEY,
      { expiresIn: '15m' },
    );

    if (sendEmails) {
      await emailService.send({
        email: oldEmail,
        subject: 'Your email was changed',
        html: `
          <h2>Email Change Notification</h2>
          <p>Hello ${user.name || ''},</p>
          <p>Your account email has been changed to: <b>${user.email}</b>.</p>
          <p>If you did not request this change, contact support immediately.</p>
        `,
      });

      await emailService.send({
        email: user.email,
        subject: 'Email change successful',
        html: `
          <h2>Welcome, ${user.name || ''}!</h2>
          <p>Your email has been successfully updated to this address.</p>
          <p>If you did not make this change, contact support immediately.</p>
        `,
      });
    }

    const plainUser = user.toJSON();

    console.log('user.toJSON()', plainUser);

    res.json({ user: plainUser, accessToken });
  } catch (err) {
    console.error('Update profile error:', err);
    next(err);
  }
}

export const authController = {
  register,
  activate,
  login,
  refresh,
  logout,
  requestReset,
  resetPassword,
  updateProfile,
};
