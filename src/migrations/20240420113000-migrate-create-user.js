'use strict';
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('User', {
      id: {
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4,
        primaryKey: true,
        allowNull: false
      },
      email: {
        type: Sequelize.STRING,
        allowNull: false
      },
      password: {
        type: Sequelize.STRING,
        allowNull: false
      },
      firstName: {
        type: Sequelize.STRING
      },
      lastName: {
        type: Sequelize.STRING
      },
      gender: {
        type: Sequelize.STRING
      },
      dateOfBirth: {
        type: Sequelize.DATE
      },
      roleId: {
        type: Sequelize.UUID,  // Sử dụng UUID cho roleId
        references: {
          model: 'Role',
          key: 'id'
        },
        onDelete: 'SET NULL'  // Khi Role bị xóa, thiết lập roleId của User thành NULL
      },
      refreshToken: {
        type: Sequelize.STRING
      },
      refreshTokenExpiresAt: {
        type: Sequelize.DATE
      },
      picture: {
        type: Sequelize.STRING,
        defaultValue: 'https://imgcdn.stablediffusionweb.com/2024/5/17/f5fb790b-36d9-4504-9ad0-d1142269fe98.jpg'
      },
      codeResetPassword: {
        type: Sequelize.STRING
      },
      otpExpiresAt: {
        type: Sequelize.DATE
      },
      createdWorkoutPlans: {
        type: Sequelize.TEXT,
        defaultValue: '[]',
        get() {
          const value = this.getDataValue('createdWorkoutPlans');
          return value ? JSON.parse(value) : [];
        },
        set(value) {
          this.setDataValue('createdWorkoutPlans', JSON.stringify(value));
        }
      },
      createdNutritionPlans: {
        type: Sequelize.TEXT,
        defaultValue: '[]',
        get() {
          const value = this.getDataValue('createdNutritionPlans');
          return value ? JSON.parse(value) : [];
        },
        set(value) {
          this.setDataValue('createdNutritionPlans', JSON.stringify(value));
        }
      },
      workoutPlanCount: {
        type: Sequelize.INTEGER,
        defaultValue: 0
      },
      nutritionPlanCount: {
        type: Sequelize.INTEGER,
        defaultValue: 0
      },
      chatCount: {
        type: Sequelize.INTEGER,
        defaultValue: 0
      },
      subscription_plan_id: {
        type: Sequelize.INTEGER,
        allowNull: true,
        defaultValue: null
      },
      subscription_expires_at: {
        type: Sequelize.DATE,
        allowNull: true,
        defaultValue: null
      },
      createdAt: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updatedAt: {
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('User');
  }
};
