const express = require('express');
const {
  getUsers,
  getUser,
  // getUserKYCTokens,
  deleteUser
} = require('../controllers/userController');
const { protect, authorize } = require('../middlewares/auth');

const router = express.Router();

router.use(protect);
router.use(authorize('admin'));

router.route('/')
  .get(getUsers);

router.route('/:id')
  .get(getUser)
  .delete(deleteUser);

// router.route('/:id/kyc')
//   .get(getUserKYCTokens);

module.exports = router;