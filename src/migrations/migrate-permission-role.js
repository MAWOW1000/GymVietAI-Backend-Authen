'use strict';
module.exports = {
  up: async (queryInterface, Sequelize) => {
    await queryInterface.createTable('Permission_Role', {
      id: {
        allowNull: false,
        primaryKey: true,
        type: Sequelize.UUID,
        defaultValue: Sequelize.UUIDV4  // UUIDV4 để tự động tạo giá trị UUID
      },
      roleId: {
        type: Sequelize.UUID,  // Sử dụng UUID cho roleId
        references: {
          model: 'Role',  // Đảm bảo tên model là 'Role'
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'  // Thêm tùy chọn onUpdate
      },
      permissionId: {
        type: Sequelize.UUID,  // Sử dụng UUID cho permissionId
        references: {
          model: 'Permission',  // Đảm bảo tên model là 'Permission'
          key: 'id'
        },
        onDelete: 'CASCADE',
        onUpdate: 'CASCADE'  // Thêm tùy chọn onUpdate
      },
      createdAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      },
      updatedAt: {
        allowNull: false,
        type: Sequelize.DATE,
        defaultValue: Sequelize.NOW
      }
    });
  },
  down: async (queryInterface, Sequelize) => {
    await queryInterface.dropTable('Permission_Role');
  }
};
