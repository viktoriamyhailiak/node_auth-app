import { ApiError } from '../exeptions/api.error.js';
import { User } from '../models/user.module.js';
import { emailService } from '../services/email.service.js';

function getAllActivated() {
  return User.findAll({
    where: {
      activationToken: null,
    },
  });
}

function normalize({ id, email }) {
  return { id, email };
}

function findByEmail(email) {
  return User.findOne({ where: { email } });
}

async function findById(id) {
  const user = await User.findByPk(id);

  if (!user) {
    throw ApiError.badRequest('User not found');
  }

  return user;
}

async function register(name, email, password, activationToken) {
  const userExist = await findByEmail(email);

  if (userExist) {
    throw ApiError.badRequest('User already exist', {
      email: 'User already exist',
    });
  }

  await User.create({
    name,
    email,
    password,
    activationToken,
  });

  await emailService.sendActivationEmail(email, activationToken);
}

async function activate(activationToken) {
  const user = await User.findOne({ where: { activationToken } });

  if (!user) {
    throw ApiError.badRequest('Wrong activation link');
  }

  user.activationToken = null;
  await user.save();

  return user;
}

export const userService = {
  getAllActivated,
  normalize,
  findByEmail,
  register,
  activate,
  findById,
};
