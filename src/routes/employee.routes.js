const express = require('express');
const router = express.Router();
const employeeController = require('../controllers/employee.controller');
const { authenticate, authorize } = require('../middlewares/auth.middleware');
const { validateBody } = require('../middlewares/validate.middleware');
const { employeeCreateSchema, employeeUpdateSchema } = require('../utils/validators');

// All endpoints protected
router.use(authenticate);

// List & Create
router.get('/', employeeController.listEmployees);
router.post('/', authorize(['admin', 'hr', 'manager']), validateBody(employeeCreateSchema), employeeController.createEmployee);

// Item operations
router.get('/:id', employeeController.getEmployee);
router.put('/:id', authorize(['admin', 'hr', 'manager']), validateBody(employeeUpdateSchema), employeeController.updateEmployee);
router.delete('/:id', authorize(['admin', 'hr']), employeeController.deleteEmployee);

module.exports = router;