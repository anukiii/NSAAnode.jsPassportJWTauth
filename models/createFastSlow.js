const mongoose = require('mongoose');
const scryptMcf = require('scrypt-mcf');
const User = require('./User.js'); 

const mongoDB = 'mongodb+srv://aluma98:YO9aIr9ieS9tF05A@cluster0.cli1tam.mongodb.net/local_library?retryWrites=true&w=majority'; //change this for usage
mongoose.connect(mongoDB, { useNewUrlParser: true, useUnifiedTopology: true });

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'MongoDB connection error:'));

async function createUser(username, password, fast = true) {
    try {
        // Define scrypt parameters for fast and slow configurations
        const fastParams = { derivedKeyLength: 64, scryptParams: { logN: 14, r: 8, p: 1 } }; // Fast configuration
        const slowParams = { derivedKeyLength: 64, scryptParams: { logN: 20, r: 8, p: 1 } }; // Slow configuration
        const scryptOptions = fast ? fastParams : slowParams;
        
        const hashedPassword = await scryptMcf.hash(password, scryptOptions);
        const user = new User({
            username: username,
            hashedPassword: hashedPassword
        });

        await user.save();
        console.log(`${fast ? 'Fast' : 'Slow'} user created`);
    } catch (error) {
        console.error('Error creating the user:', error);
    }
}

// create fast and slow users
createUser('fast', 'password', true)
createUser('slow', 'password', false)
db.close();

