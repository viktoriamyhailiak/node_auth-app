import { userService } from '../services/user.service.js';

const getAllActivated = async (req, res) => {
  const users = await userService.getAllActivated();

  res.send(users.map(userService.normalize));
};

const activate = async (req, res, next) => {
  try {
    const { token } = req.params;
    const user = await userService.activate(token);

    res.json({ message: 'User activated', user: userService.normalize(user) });
  } catch (e) {
    next(e);
  }
};

export const userController = {
  getAllActivated,
  activate,
};
