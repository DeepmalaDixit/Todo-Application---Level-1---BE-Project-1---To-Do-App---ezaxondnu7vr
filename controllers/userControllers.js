const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../models/user');

const JWT_SECRET = 'some_secret_key';

const signupUser = async (req, res) => {
  const { name, email, password, role } = req.body;

  try {
    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: 'User with given Email already registered', status: 'fail' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = new User({ name, email, password: hashedPassword, role });

    // Save user
    await newUser.save();

    return res.status(200).json({ message: 'User SignedUp successfully', status: 'success' });
  } catch (error) {
    console.error(error);
    return res.status(404).json({ message: 'Something went wrong', status: 'fail' });
  }
};

const loginUser = async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: 'User with this E-mail does not exist !!', status: 'fail' });
    }

    // Compare password
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(403).json({ message: 'Invalid Password, try again !!', status: 'fail' });
    }

    // Create and sign token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });

    return res.status(200).json({ status: 'success', token });
  } catch (error) {
    console.error(error);
    return res.status(404).json({ message: 'Something went wrong', status: 'fail' });
  }
};

module.exports = { signupUser, loginUser };
