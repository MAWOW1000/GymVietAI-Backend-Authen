// src/controller/dashboardController.js
const { User, Role } = require('../models');
const { Op } = require('sequelize');

module.exports = {
    // Tổng số người dùng
    getTotalUsers: async (req, res) => {
        try {
            const totalUsers = await User.count();
            res.json({ totalUsers });
        } catch (error) {
            console.error('Error in getTotalUsers:', error);
            res.status(500).json({ error: 'Lỗi server' });
        }
    },

    // Thống kê số lượng người dùng có workout plans và nutrition plans
    getPlanStats: async (req, res) => {
        try {
            const [usersWithWorkoutPlans, usersWithNutritionPlans] = await Promise.all([
                User.count({
                    where: {
                        workoutPlanCount: { $gt: 0 }
                    }
                }),
                User.count({
                    where: {
                        nutritionPlanCount: { $gt: 0 }
                    }
                })
            ]);

            res.json({
                usersWithWorkoutPlans,
                usersWithNutritionPlans
            });
        } catch (error) {
            console.error('Error in getPlanStats:', error);
            res.status(500).json({ error: 'Lỗi server' });
        }
    },

    // Thống kê theo vai trò (Role)
    getUserRoleStats: async (req, res) => {
        try {
            const roles = await Role.findAll();
            const stats = {};

            await Promise.all(
                roles.map(async (role) => {
                    const count = await User.count({ where: { roleId: role.id } });
                    stats[role.name] = count;
                })
            );

            res.json(stats);
        } catch (error) {
            console.error('Error in getUserRoleStats:', error);
            res.status(500).json({ error: 'Lỗi server' });
        }
    },

    // Thống kê theo gói subscription
    getSubscriptionStats: async (req, res) => {
        try {
            const withSubscription = await User.count({
                where: {
                    subscription_plan_id: { $ne: null }
                }
            });

            const withoutSubscription = await User.count({
                where: {
                    subscription_plan_id: null
                }
            });

            res.json({
                withSubscription,
                withoutSubscription
            });
        } catch (error) {
            console.error('Error in getSubscriptionStats:', error);
            res.status(500).json({ error: 'Lỗi server' });
        }
    },

    // Thống kê theo giới tính
    getGenderStats: async (req, res) => {
        try {
            const male = await User.count({ where: { gender: 'male' } });
            const female = await User.count({ where: { gender: 'female' } });

            const other = await User.count({
                where: {
                    gender: {
                        [Op.notIn]: ['male', 'female']
                    }
                }
            });

            return res.status(200).json({
                Male: male,
                Female: female,
                Other: other,
            });
        } catch (error) {
            console.error("Error in getGenderStats:", error);
            return res.status(500).json({ error: "Lỗi server" });
        }
    }

};