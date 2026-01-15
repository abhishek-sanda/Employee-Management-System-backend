const Employee = require('../models/employee.model');
const mongoose = require('mongoose');

/**
 * Utility: mask sensitive fields by role
 * - admin & hr can see salary & ssn
 * - others see masked strings
 */
function maskSensitive(emp, user) {
  const copy = { ...emp };
  const canSeeSensitive = user && ['admin', 'hr'].includes(user.role);
  if (!canSeeSensitive) {
    if (copy.salary !== undefined) copy.salary = '****';
    if (copy.ssn !== undefined) copy.ssn = '****';
  }
  return copy;
}

/**
 * Respond helper for duplicate key errors (11000)
 */
function handleDuplicateKeyError(err, res) {
  if (err && err.code === 11000) {
    const key = Object.keys(err.keyValue || {})[0];
    const val = err.keyValue ? err.keyValue[key] : '';
    return res.status(409).json({ success: false, message: `Duplicate value for ${key}: ${val}` });
  }
  return null;
}

// Create
exports.createEmployee = async (req, res, next) => {
  try {
    const payload = { ...req.body, createdBy: req.user._id };
    const employee = await Employee.create(payload);
    // populate manager minimally for response
    const populated = await Employee.findById(employee._id).populate('managerId', 'employeeId firstName lastName').lean();
    return res.status(201).json({ success: true, data: maskSensitive(populated, req.user) });
  } catch (err) {
    const dup = handleDuplicateKeyError(err, res);
    if (dup) return dup;
    return next(err);
  }
};

// List with pagination, search and optional sorting
exports.listEmployees = async (req, res, next) => {
  try {
    const { page = 1, limit = 20, q, sortBy = 'createdAt', sortDir = 'desc' } = req.query;
    const filter = {};

    if (q) {
      const re = new RegExp(q, 'i');
      filter.$or = [
        { firstName: re },
        { lastName: re },
        { email: re },
        { employeeId: re },
        { department: re }
      ];
    }

    const skip = (Number(page) - 1) * Number(limit);
    const sort = { [sortBy]: sortDir === 'asc' ? 1 : -1 };

    const [items, total] = await Promise.all([
      Employee.find(filter)
        .populate('managerId', 'employeeId firstName lastName')
        .sort(sort)
        .skip(skip)
        .limit(Number(limit))
        .lean(),
      Employee.countDocuments(filter)
    ]);

    const data = items.map((it) => maskSensitive(it, req.user));
    res.json({ success: true, data, meta: { page: Number(page), limit: Number(limit), total } });
  } catch (err) {
    next(err);
  }
};

// Get by id
exports.getEmployee = async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const emp = await Employee.findById(id).populate('managerId', 'employeeId firstName lastName').lean();
    if (!emp) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true, data: maskSensitive(emp, req.user) });
  } catch (err) {
    next(err);
  }
};

// Update
exports.updateEmployee = async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const update = { ...req.body, updatedBy: req.user._id };
    const emp = await Employee.findByIdAndUpdate(id, update, { new: true }).populate('managerId', 'employeeId firstName lastName').lean();
    if (!emp) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true, data: maskSensitive(emp, req.user) });
  } catch (err) {
    const dup = handleDuplicateKeyError(err, res);
    if (dup) return dup;
    next(err);
  }
};

// Soft delete
exports.deleteEmployee = async (req, res, next) => {
  try {
    const { id } = req.params;
    if (!mongoose.Types.ObjectId.isValid(id)) return res.status(400).json({ success: false, message: 'Invalid id' });

    const emp = await Employee.findByIdAndUpdate(id, { status: 'inactive', updatedBy: req.user._id }, { new: true }).populate('managerId', 'employeeId firstName lastName').lean();
    if (!emp) return res.status(404).json({ success: false, message: 'Not found' });
    res.json({ success: true, data: maskSensitive(emp, req.user) });
  } catch (err) {
    next(err);
  }
};