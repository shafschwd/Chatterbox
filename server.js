// server.js - Main server file
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "http://localhost:3000", // Frontend URL
    methods: ["GET", "POST"]
  }
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve static files

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chatbox', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  isOnline: { type: Boolean, default: false }
});

// Message Schema
const messageSchema = new mongoose.Schema({
  content: { type: String, required: true },
  sender: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  room: { type: String, required: true }, // 'general' for public, or group ID
  timestamp: { type: Date, default: Date.now },
  messageType: { type: String, enum: ['text', 'image', 'file'], default: 'text' }
});

// Room/Group Schema
const roomSchema = new mongoose.Schema({
  name: { type: String, required: true },
  description: { type: String },
  members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  admin: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  createdAt: { type: Date, default: Date.now },
  isPrivate: { type: Boolean, default: false }
});

const User = mongoose.model('User', userSchema);
const Message = mongoose.model('Message', messageSchema);
const Room = mongoose.model('Room', roomSchema);

// JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// Socket Authentication Middleware
const authenticateSocket = async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.userId);
    if (!user) {
      return next(new Error('User not found'));
    }
    socket.userId = user._id;
    socket.username = user.username;
    next();
  } catch (err) {
    next(new Error('Authentication error'));
  }
};

// Routes

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'All fields are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await User.findOne({ 
      $or: [{ email }, { username }] 
    });

    if (existingUser) {
      return res.status(400).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create user
    const user = new User({
      username,
      email,
      password: hashedPassword
    });

    await user.save();

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Check password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }

    // Update online status
    await User.findByIdAndUpdate(user._id, { isOnline: true });

    // Generate JWT token
    const token = jwt.sign(
      { userId: user._id, username: user.username },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// User Logout
app.post('/api/logout', authenticateToken, async (req, res) => {
  try {
    // Update online status
    await User.findByIdAndUpdate(req.user.userId, { isOnline: false });
    res.json({ message: 'Logout successful' });
  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get chat history
app.get('/api/messages/:room', authenticateToken, async (req, res) => {
  try {
    const { room } = req.params;
    const { page = 1, limit = 50 } = req.query;

    const messages = await Message.find({ room })
      .populate('sender', 'username')
      .sort({ timestamp: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    res.json(messages.reverse());
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create room/group
app.post('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const { name, description, isPrivate = false } = req.body;

    const room = new Room({
      name,
      description,
      admin: req.user.userId,
      members: [req.user.userId],
      isPrivate
    });

    await room.save();
    await room.populate('members', 'username');

    res.status(201).json(room);
  } catch (error) {
    console.error('Create room error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get user's rooms
app.get('/api/rooms', authenticateToken, async (req, res) => {
  try {
    const rooms = await Room.find({
      members: req.user.userId
    }).populate('members', 'username');

    res.json(rooms);
  } catch (error) {
    console.error('Get rooms error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Socket.IO Connection Handling
io.use(authenticateSocket);

io.on('connection', async (socket) => {
  console.log(`User ${socket.username} connected`);

  // Update user online status
  await User.findByIdAndUpdate(socket.userId, { isOnline: true });

  // Join default room
  socket.join('general');

  // Notify others of user joining
  socket.to('general').emit('user_joined', {
    username: socket.username,
    message: `${socket.username} joined the chat`
  });

  // Handle joining rooms
  socket.on('join_room', async (roomId) => {
    try {
      const room = await Room.findById(roomId);
      if (room && room.members.includes(socket.userId)) {
        socket.join(roomId);
        socket.emit('joined_room', { roomId, roomName: room.name });
      }
    } catch (error) {
      console.error('Join room error:', error);
    }
  });

  // Handle sending messages
  socket.on('send_message', async (data) => {
    try {
      const { content, room = 'general' } = data;

      // Save message to database
      const message = new Message({
        content,
        sender: socket.userId,
        room
      });

      await message.save();
      await message.populate('sender', 'username');

      // Emit message to room
      io.to(room).emit('new_message', {
        id: message._id,
        content: message.content,
        sender: {
          id: message.sender._id,
          username: message.sender.username
        },
        room: message.room,
        timestamp: message.timestamp
      });
    } catch (error) {
      console.error('Send message error:', error);
      socket.emit('error', { message: 'Failed to send message' });
    }
  });

  // Handle typing indicators
  socket.on('typing', (data) => {
    socket.to(data.room || 'general').emit('user_typing', {
      username: socket.username,
      room: data.room || 'general'
    });
  });

  socket.on('stop_typing', (data) => {
    socket.to(data.room || 'general').emit('user_stop_typing', {
      username: socket.username,
      room: data.room || 'general'
    });
  });

  // Handle disconnect
  socket.on('disconnect', async () => {
    console.log(`User ${socket.username} disconnected`);
    
    // Update user offline status
    await User.findByIdAndUpdate(socket.userId, { isOnline: false });
    
    // Notify others
    socket.broadcast.emit('user_left', {
      username: socket.username,
      message: `${socket.username} left the chat`
    });
  });
});

// Start server
const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});