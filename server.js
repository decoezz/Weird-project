const mongoose = require('mongoose');
const dotenv = require('dotenv');
const app = require('./app');
process.on('uncaughtException', (err) => {
  console.log('Shutting down due to an uncaught exception... 💣');
  console.log(err.name, err.message);
  process.exit(1);
});
dotenv.config({ path: './config.env' });
const DB = process.env.DATABASE.replace(
  '<PASSWORD>',
  process.env.DATABASE_PASSWORD
);
mongoose.connect(DB).then(console.log('SERVER CONNECTED SUCCESSFULLY'));
const port = process.env.PORT || 3000;
const server = app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

process.on('unhandledRejection', (err) => {
  console.log('Shutting down due to an unhandled rejection... 💣');
  console.log(err.name, err.message);
  server.close(() => {
    process.exit(1);
  });
});
