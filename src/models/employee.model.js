const mongoose = require('mongoose');

const AddressSchema = new mongoose.Schema({
  line1: String,
  line2: String,
  city: String,
  state: String,
  zip: String,
  country: String
});

const EmployeeSchema = new mongoose.Schema(
  {
    employeeId: { type: String, required: true, unique: true, index: true },
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true, lowercase: true, trim: true },
    phone: { type: String },
    position: { type: String },
    department: { type: String },
    managerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee' },
    hireDate: { type: Date },
    salary: { type: Number }, // sensitive: mask in responses / restrict access in controller
    ssn: { type: String }, // sensitive: for production encrypt or store in vault
    address: AddressSchema,
    status: { type: String, enum: ['active', 'inactive', 'terminated'], default: 'active' },
    photoUrl: { type: String },
    metadata: { type: Object },
    createdBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    updatedBy: { type: mongoose.Schema.Types.ObjectId, ref: 'User' }
  },
  { timestamps: true }
);

module.exports = mongoose.model('Employee', EmployeeSchema);