const express = require('express');
const router = express.Router();
const { check, validationResult } = require('express-validator'); // Backend validation
const { md5 } = require('../auth/utils');
const { config} = require('../config');
const db = require('../database/db');


// 创建一个新用户 (只有 admin 账号拥有权限)
router.post('/user', [
  check('name')
    .isLength({ min: 5 })
  .withMessage('Username must be at least 5 characters long'),
  check('password')
    .isLength({ min: 5 })
  .withMessage('Password must be at least 5 characters long'),
  check('group')
    .custom(value => {
      if (value !== 'user' && value !== 'guest') {
        throw new Error(`User group name must be one of ['user', 'guest'].`)
      }
      return true
    })
], (req, res, next) => {
  // Finds the validation errors in this request and wraps them in an object with handy functions
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).send({ errors: errors.array() });
  }

  const user = {
    name: req.body.name,
    password: req.body.password,
    group: req.body.group
  };

  if (!config.auth || req.user.name === 'admin') {
    db.createUser({
      name: user.name,
      password: md5(user.password),
      group: user.group
    })
  .then(() => res.send({ message: `User ${user.name} created successfully.` }))
      .catch((err) => {
        if (err.message.indexOf('already exists') !== -1) {
          res.status(403).send({ error: err.message });
        } else {
          next(err);
        }
      });
  } else {
  res.status(403).send({ error: 'Only the admin account can create new users.' });
  }
});

// 更新用户密码
router.put('/user', [
  check('name')
    .isLength({ min: 5 })
  .withMessage('Username must be at least 5 characters long'),
  check('newPassword')
    .isLength({ min: 5 })
  .withMessage('Password must be at least 5 characters long')
], (req, res, next) => {
  // Finds the validation errors in this request and wraps them in an object with handy functions
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(422).json({errors: errors.array()});
  }

  const user = {
    name: req.body.name
  };
  const newPassword = md5(req.body.newPassword);

  if (!config.auth || req.user.name === 'admin' || req.user.name === user.name) {
    db.updateUserPassword(user, newPassword)
  .then(() => res.send({ message: 'Password updated successfully.' }))
      .catch((err) => {
        if (err.message.indexOf('Username incorrect.') !== -1) {
          res.status(403).send({ error: 'Username incorrect.' });
        } else {
          next(err);
        }
      });
  } else {
  res.status(403).send({ error: 'You can only change your own password.' });
  }
});

// 删除用户 (仅 admin 账号拥有权限)
router.delete('/user', (req, res, next) => {
  const users = req.body.users

  if (!config.auth || req.user.name === 'admin') {
    if (!users.find(user => user.name === 'admin')) {
      db.deleteUser(users)
        .then(() => {
          res.send({ message: 'Deleted successfully.' });  
        })
        .catch((err) => {
          next(err);
        });
    } else {
  res.status(403).send({ error: 'Cannot delete the built-in admin account.' });
    }
  } else {
  res.status(403).send({ error: 'Only the admin account can delete users.' });
  }
});

// 获取所有用户
router.get('/users', (req, res, next) => {
  if (!config.auth || req.user.name === 'admin') {
    db.knex('t_user')
    .select('name', 'group')
    .then((users) => {
      res.send({ users });
    })
    .catch((err) => {
      next(err);
    });
  } else {
  res.status(403).send({ error: 'Only the admin account can view users.' });
  }
});

module.exports = router;