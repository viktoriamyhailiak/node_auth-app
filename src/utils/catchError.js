export const catchError = (action) => {
  return function (req, res, next) {
    try {
      action(req, res, next);
    } catch (e) {
      next(e);
    }
  };
};
