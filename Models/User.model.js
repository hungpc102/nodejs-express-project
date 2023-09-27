const { DataTypes } = require('sequelize');
const sequelize = require('../helpers/connections_mssql');
const bcrypt = require('bcrypt')

const UserSchema = sequelize.define('USERS', {
  USER_ID: { // Đổi tên cột thành USER_ID
    type: DataTypes.INTEGER, // Dựa vào kiểu dữ liệu thực tế của cột USER_ID
    allowNull: false,
    primaryKey: true, // Đây là cột primary key
    autoIncrement: true, // Nếu cột này là auto-increment
    field: 'USER_ID', // Đặt tên cột trong SQL Server
    unique: true, 

  },
  USER_NAME: {
    type: DataTypes.STRING,
    allowNull: true,

  },
  USER_EMAIL: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true, 
     set(value) {
      this.setDataValue('USER_EMAIL', value.toLowerCase())
    }
  },
  USER_PASSWORD: {
    type: DataTypes.STRING,
    allowNull: false,
   

  },
  USER_PHONE: {
    type: DataTypes.STRING,
    allowNull: true,
    unique: true ,


  },
}, {
  // Đặt tên bảng SQL nếu bạn muốn sử dụng tên bảng khác
  tableName: 'USERS',
  timestamps: false, // Nếu bạn không sử dụng các trường timestamps (createdAt, updatedAt)
});

UserSchema.beforeCreate(async (user, options) => {
  try {
    console.log(`Called before create`, user.USER_EMAIL, user.USER_PASSWORD);
    const salt = await bcrypt.genSalt(10);
    const hashPassword = await bcrypt.hash(user.USER_PASSWORD, salt);
    user.USER_PASSWORD = hashPassword;
  } catch (error) {
    throw error; 
  }
});

UserSchema.prototype.isCheckPassword = async function(password) {
  try {
    return await bcrypt.compare(password, this.USER_PASSWORD);
  } catch (error) {
    throw new Error('Error comparing passwords');
  }
};

module.exports = UserSchema;
