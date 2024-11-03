const express = require('express');
const router = express.Router();
const userController = require('../controllers/userControllers');
const authMiddleware = require('../utils/authMiddleware');

// Route to get the user's profile
router.get('/profile', userController.getUserProfile);

// Route to update the user's profile
router.put('/profile', userController.updateUserProfile);

// Route to get skill progress for the logged-in user
router.get('/skill-progress', userController.getSkillProgress);

// Route to update skill progress
router.put('/skill-progress', userController.updateSkillProgress);

// Route to join a community/group
router.post('/join-community', userController.joinCommunity);

// Route to leave a community/group
router.post('/leave-community', userController.leaveCommunity);

// Route to get user-specific dashboard data
router.get('/dashboard', userController.getDashboard);

module.exports = router;

// Block/Unblock a User
router.post('/block-user',userController.blockUser);

// Delete User Account
router.delete('/delete-account',userController.deleteUserAccount);

module.exports = router;