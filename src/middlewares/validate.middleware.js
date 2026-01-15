const Joi = require('joi');

exports.validateBody = (schema) => {
  return (req, res, next) => {
    const result = schema.validate(req.body, { abortEarly: false, stripUnknown: true });
    if (result.error) {
      return res.status(400).json({
        success: false,
        error: result.error.details.map((d) => d.message)
      });
    }
    req.body = result.value;
    next();
  };
};