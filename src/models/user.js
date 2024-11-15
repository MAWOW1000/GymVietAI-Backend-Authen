'use strict';
const {
  Model
} = require('sequelize');
module.exports = (sequelize, DataTypes) => {
  class User extends Model {
    /**
     * Helper method for defining associations.
     * This method is not a part of Sequelize lifecycle.
     * The `models/index` file will call this method automatically.
     */
    static associate(models) {
      // define association here
      User.belongsTo(models.Role);
    }
  };
  //object relational mapping
  User.init({
    email: DataTypes.STRING,
    password: DataTypes.STRING,
    firstName: DataTypes.STRING,
    lastName: DataTypes.STRING,
    gender: DataTypes.STRING,
    dateOfBirth: DataTypes.DATE,
    roleId: DataTypes.INTEGER,
    refreshToken: DataTypes.STRING,
    codeResetPassword: DataTypes.STRING,
    typeLogin: {
      type: DataTypes.STRING,
      defaultValue: 'LOCAL'
    }
  }, {
    sequelize,
    modelName: 'User',
  });
  return User;
};