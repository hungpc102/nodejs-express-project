const { Sequelize } = require('sequelize');
require('dotenv').config()

// Thông tin kết nối SQL Server
const sequelize = new Sequelize('DB_FOOD', 'sa', '123456aA@$', {
  host: 'localhost',
  dialect: 'mssql',
  dialectOptions: {
    driver: 'msnodesqlv8'
  },
});


// Kết nối cơ sở dữ liệu
sequelize.authenticate()
  .then(() => {
    console.log('Connected to SQL Server');
  })
  .catch(err => {
    console.error('Error connecting to SQL Server', err);
  });

  process.on('SIGINT', async () => {
      await sequelize.close();
      console.log('Connection to SQL Server closed.');
      process.exit(0);
  });
module.exports = sequelize;
