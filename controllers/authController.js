const User = require('/home/anuki/webserver/models/User.js');
const scryptMcf = require('scrypt-mcf');

exports.loginUser = async (username, password) => {
  try {
    const user = await User.findOne({ username: username }).exec();
    if (!user) {
      return null; 
    }
    const match = await scryptMcf.verify(password, user.hashedPassword);
    if (match) {
      return user; 
    }
    return null; 
  } catch (error) {
    throw error;
  }
};
