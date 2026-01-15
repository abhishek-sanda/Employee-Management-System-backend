const Joi = require('joi');

const objectIdPattern = /^[0-9a-fA-F]{24}$/;

const registerSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().min(8).required(),
  role: Joi.string().valid('admin', 'hr', 'manager', 'employee').default('employee')
});

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

const addressSchema = Joi.object({
  line1: Joi.string().allow('', null),
  line2: Joi.string().allow('', null),
  city: Joi.string().allow('', null),
  state: Joi.string().allow('', null),
  zip: Joi.string().allow('', null),
  country: Joi.string().allow('', null)
});

const employeeCreateSchema = Joi.object({
  employeeId: Joi.string().trim().required(),
  firstName: Joi.string().min(1).max(100).required(),
  lastName: Joi.string().min(1).max(100).required(),
  email: Joi.string().email().required(),
  phone: Joi.string().allow('', null),
  position: Joi.string().allow('', null),
  department: Joi.string().allow('', null),
  managerId: Joi.string().pattern(objectIdPattern).optional().allow('', null),
  hireDate: Joi.date().less('now').optional(),
  salary: Joi.number().min(0).optional(),
  ssn: Joi.string().optional(),
  address: addressSchema.optional(),
  status: Joi.string().valid('active', 'inactive', 'terminated').optional(),
  photoUrl: Joi.string().uri().optional(),
  metadata: Joi.object().optional()
});

const employeeUpdateSchema = employeeCreateSchema.fork(Object.keys(employeeCreateSchema.describe().keys), (s) => s.optional());

module.exports = {
  registerSchema,
  loginSchema,
  employeeCreateSchema,
  employeeUpdateSchema
};