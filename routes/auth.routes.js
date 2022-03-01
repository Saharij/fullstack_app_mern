const { Router, response } = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const config = require('config');
const { check, validationResult } = require('express-validator');
const User = require('../models/User');
const router = Router();

// /api/auth/register
router.post(
  '/register',
  [
    check('email', 'Якісь василь написав галімий емейл').isEmail(),
    check('password', 'Якісь василь написав галімий пароль').isLength({ min: 6 }),
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Якісь василь написав галімі дані'
      });
    }

    const { email, password } = req.body;
    const candidate = await User.findOne({ email });

    if (candidate) {
      return res.status(400).json({ message: 'Цей користувач вже існує' });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hashedPassword });

    await user.save();
    res.status(201).json({ message: 'Створено новий користувач' });

  } catch (e) {
    res.status(500).json({ message: 'Something went wrong!' });
  }
});

// /api/auth/login
router.post(
  '/login',
  [
    check('email', 'Напиши нормальну пошту, не будь васильом').normalizeEmail().isEmail(),
    check('password', 'Не будь васильом, напиши пароль').exists(),
  ],
  async (req, res) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        errors: errors.array(),
        message: 'Sorry you specified incorect data'
      });
    }

    const { email, password } = req.body;

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(400).json({ message: 'Sorry you specified incorect data' })
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Не правильний пароль спробуйте ще раз' });
    }

    const token = jwt.sign(
      { userId: user.id },
      config.get('jwtSecret'),
      { expiresIn: '1h' }
    );

    res.json({ token, userId: user.id });

  } catch (e) {
    res.status(500).json({ message: 'Something went wrong!' });
  }
});

module.exports = router;
