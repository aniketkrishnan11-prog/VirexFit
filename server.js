require('dotenv').config();
const express    = require('express');
const mongoose   = require('mongoose');
const bcrypt     = require('bcryptjs');
const jwt        = require('jsonwebtoken');
const cors       = require('cors');

const app = express();

/* ═══════════════════════════════════════════════════════════════
   MIDDLEWARE
═══════════════════════════════════════════════════════════════ */
app.use(cors({
  origin: '*', // In production set to your frontend URL
  methods: ['GET','POST','PUT','DELETE','PATCH'],
  allowedHeaders: ['Content-Type','Authorization'],
}));
app.use(express.json());
app.use(express.static('public')); // Serves VirexFit.html from /public folder

/* ═══════════════════════════════════════════════════════════════
   MONGODB CONNECTION
═══════════════════════════════════════════════════════════════ */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('✅  MongoDB connected:', process.env.MONGO_URI))
  .catch(err => {
    console.error('❌  MongoDB connection error:', err.message);
    process.exit(1);
  });

/* ═══════════════════════════════════════════════════════════════
   MONGOOSE SCHEMAS & MODELS
═══════════════════════════════════════════════════════════════ */

// ── User ────────────────────────────────────────────────────
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true, minlength: 6 },
  goal:      { type: String, default: 'Muscle Gain',
               enum: ['Muscle Gain','Fat Loss','Endurance','Strength','Athletic Performance'] },
  createdAt: { type: Date, default: Date.now },
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  this.password = await bcrypt.hash(this.password, 12);
  next();
});

// Compare password method
userSchema.methods.matchPassword = async function(enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

const User = mongoose.model('User', userSchema);

// ── Exercise ─────────────────────────────────────────────────
const exerciseSchema = new mongoose.Schema({
  name:       { type: String, required: true },
  muscle:     { type: String, required: true },
  difficulty: { type: String, enum: ['Beginner','Intermediate','Advanced'], required: true },
  equipment:  { type: String, enum: ['Bodyweight','Dumbbells','Barbell','Machines'], required: true },
  calories:   { type: Number, required: true },  // kcal per set
  duration:   { type: String },                  // e.g. "3 sets × 12 reps"
  description:{ type: String },
  color:      { type: String, default: '#00c8ff' },
  animType:   { type: String, default: 'ex-push' },
  emoji:      { type: String, default: '💪' },
}, { timestamps: true });

const Exercise = mongoose.model('Exercise', exerciseSchema);

// ── Cart Item ─────────────────────────────────────────────────
const cartItemSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  exerciseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Exercise', required: true },
  sets:       { type: Number, default: 3, min: 1, max: 99 },
  reps:       { type: Number, default: 12, min: 1, max: 999 },
  order:      { type: Number, default: 0 },
}, { timestamps: true });

// One user can have each exercise only once in cart
cartItemSchema.index({ userId: 1, exerciseId: 1 }, { unique: true });

const CartItem = mongoose.model('CartItem', cartItemSchema);

// ── Workout Session ────────────────────────────────────────────
const workoutSessionSchema = new mongoose.Schema({
  userId:     { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  exercises:  [{
    exerciseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Exercise' },
    name:       String,
    sets:       Number,
    reps:       Number,
    caloriesBurned: Number,
  }],
  totalCalories: { type: Number, default: 0 },
  completedAt:   { type: Date, default: Date.now },
}, { timestamps: true });

const WorkoutSession = mongoose.model('WorkoutSession', workoutSessionSchema);

/* ═══════════════════════════════════════════════════════════════
   JWT MIDDLEWARE
═══════════════════════════════════════════════════════════════ */
const protect = async (req, res, next) => {
  let token;
  if (req.headers.authorization?.startsWith('Bearer ')) {
    token = req.headers.authorization.split(' ')[1];
  }
  if (!token) return res.status(401).json({ success: false, message: 'Not authorized. No token.' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = await User.findById(decoded.id).select('-password');
    if (!req.user) return res.status(401).json({ success: false, message: 'User not found.' });
    next();
  } catch (err) {
    return res.status(401).json({ success: false, message: 'Token invalid or expired.' });
  }
};

// Helper: generate JWT
const generateToken = (id) =>
  jwt.sign({ id }, process.env.JWT_SECRET, { expiresIn: '30d' });

/* ═══════════════════════════════════════════════════════════════
   ROUTES — AUTH
═══════════════════════════════════════════════════════════════ */

// POST /api/auth/register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ success: false, message: 'All fields are required.' });
    if (password.length < 6)
      return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });

    const exists = await User.findOne({ email });
    if (exists)
      return res.status(400).json({ success: false, message: 'Email already registered.' });

    const user = await User.create({ name, email, password });
    res.status(201).json({
      success: true,
      message: 'Account created successfully!',
      token: generateToken(user._id),
      user: { id: user._id, name: user.name, email: user.email, goal: user.goal },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/auth/login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ success: false, message: 'Email and password required.' });

    const user = await User.findOne({ email });
    if (!user || !(await user.matchPassword(password)))
      return res.status(401).json({ success: false, message: 'Invalid email or password.' });

    res.json({
      success: true,
      message: 'Login successful!',
      token: generateToken(user._id),
      user: { id: user._id, name: user.name, email: user.email, goal: user.goal },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/auth/me
app.get('/api/auth/me', protect, (req, res) => {
  res.json({ success: true, user: { id: req.user._id, name: req.user.name, email: req.user.email, goal: req.user.goal } });
});

/* ═══════════════════════════════════════════════════════════════
   ROUTES — EXERCISES
═══════════════════════════════════════════════════════════════ */

// GET /api/exercises  — list with optional filters
app.get('/api/exercises', async (req, res) => {
  try {
    const filter = {};
    if (req.query.muscle     && req.query.muscle     !== 'All') filter.muscle     = req.query.muscle;
    if (req.query.difficulty && req.query.difficulty !== 'All') filter.difficulty = req.query.difficulty;
    if (req.query.equipment  && req.query.equipment  !== 'All') filter.equipment  = req.query.equipment;
    if (req.query.q) {
      filter.$or = [
        { name:   { $regex: req.query.q, $options: 'i' } },
        { muscle: { $regex: req.query.q, $options: 'i' } },
      ];
    }
    const exercises = await Exercise.find(filter).sort({ name: 1 });
    res.json({ success: true, count: exercises.length, exercises });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/exercises/:id
app.get('/api/exercises/:id', async (req, res) => {
  try {
    const exercise = await Exercise.findById(req.params.id);
    if (!exercise) return res.status(404).json({ success: false, message: 'Exercise not found.' });
    res.json({ success: true, exercise });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════════
   ROUTES — CART  (protected)
═══════════════════════════════════════════════════════════════ */

// GET /api/cart
app.get('/api/cart', protect, async (req, res) => {
  try {
    const items = await CartItem.find({ userId: req.user._id })
      .populate('exerciseId')
      .sort({ order: 1 });
    res.json({ success: true, count: items.length, cart: items });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// POST /api/cart  — add exercise to cart
app.post('/api/cart', protect, async (req, res) => {
  try {
    const { exerciseId, sets = 3, reps = 12 } = req.body;
    if (!exerciseId) return res.status(400).json({ success: false, message: 'exerciseId is required.' });

    const exercise = await Exercise.findById(exerciseId);
    if (!exercise) return res.status(404).json({ success: false, message: 'Exercise not found.' });

    const existingCount = await CartItem.countDocuments({ userId: req.user._id });
    const item = await CartItem.create({
      userId: req.user._id, exerciseId, sets, reps, order: existingCount,
    });
    await item.populate('exerciseId');
    res.status(201).json({ success: true, message: `${exercise.name} added to cart!`, item });
  } catch (err) {
    if (err.code === 11000)
      return res.status(400).json({ success: false, message: 'Exercise already in cart.' });
    res.status(500).json({ success: false, message: err.message });
  }
});

// PATCH /api/cart/:itemId  — update sets/reps
app.patch('/api/cart/:itemId', protect, async (req, res) => {
  try {
    const { sets, reps } = req.body;
    const item = await CartItem.findOne({ _id: req.params.itemId, userId: req.user._id });
    if (!item) return res.status(404).json({ success: false, message: 'Cart item not found.' });

    if (sets !== undefined) item.sets = Math.max(1, Math.min(99, sets));
    if (reps !== undefined) item.reps = Math.max(1, Math.min(999, reps));
    await item.save();
    await item.populate('exerciseId');
    res.json({ success: true, item });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/cart/:itemId
app.delete('/api/cart/:itemId', protect, async (req, res) => {
  try {
    const item = await CartItem.findOneAndDelete({ _id: req.params.itemId, userId: req.user._id });
    if (!item) return res.status(404).json({ success: false, message: 'Cart item not found.' });
    res.json({ success: true, message: 'Exercise removed from cart.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// DELETE /api/cart  — clear entire cart
app.delete('/api/cart', protect, async (req, res) => {
  try {
    await CartItem.deleteMany({ userId: req.user._id });
    res.json({ success: true, message: 'Cart cleared.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/cart/reorder  — drag & drop new order
app.put('/api/cart/reorder', protect, async (req, res) => {
  try {
    const { orderedIds } = req.body; // array of cart item IDs in new order
    if (!Array.isArray(orderedIds))
      return res.status(400).json({ success: false, message: 'orderedIds must be an array.' });

    const updates = orderedIds.map((id, index) =>
      CartItem.findOneAndUpdate(
        { _id: id, userId: req.user._id },
        { order: index },
        { new: true }
      )
    );
    await Promise.all(updates);
    res.json({ success: true, message: 'Cart reordered.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════════
   ROUTES — WORKOUT SESSIONS  (protected)
═══════════════════════════════════════════════════════════════ */

// POST /api/sessions  — save completed workout
app.post('/api/sessions', protect, async (req, res) => {
  try {
    const { exercises } = req.body;
    if (!exercises || !exercises.length)
      return res.status(400).json({ success: false, message: 'No exercises provided.' });

    const totalCalories = exercises.reduce((sum, e) => sum + (e.caloriesBurned || 0), 0);
    const session = await WorkoutSession.create({
      userId: req.user._id, exercises, totalCalories,
    });
    res.status(201).json({ success: true, message: 'Workout saved!', session });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/sessions  — workout history
app.get('/api/sessions', protect, async (req, res) => {
  try {
    const sessions = await WorkoutSession.find({ userId: req.user._id })
      .sort({ completedAt: -1 })
      .limit(20);
    res.json({ success: true, count: sessions.length, sessions });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/sessions/stats  — dashboard stats
app.get('/api/sessions/stats', protect, async (req, res) => {
  try {
    const now = new Date();
    const startOfDay   = new Date(now.setHours(0,0,0,0));
    const startOfWeek  = new Date(now); startOfWeek.setDate(now.getDate() - now.getDay());
    startOfWeek.setHours(0,0,0,0);

    const [totalSessions, weekSessions, todaySessions, allSessions] = await Promise.all([
      WorkoutSession.countDocuments({ userId: req.user._id }),
      WorkoutSession.countDocuments({ userId: req.user._id, completedAt: { $gte: startOfWeek } }),
      WorkoutSession.find({ userId: req.user._id, completedAt: { $gte: startOfDay } }),
      WorkoutSession.find({ userId: req.user._id }).sort({ completedAt: -1 }).limit(50),
    ]);

    const todayCalories  = todaySessions.reduce((s,x) => s + x.totalCalories, 0);
    const totalExercises = allSessions.reduce((s,x) => s + x.exercises.length, 0);

    // Calculate streak
    let streak = 0;
    const dateMap = new Set(allSessions.map(s => s.completedAt.toDateString()));
    for (let i = 0; i < 365; i++) {
      const d = new Date(); d.setDate(d.getDate() - i);
      if (dateMap.has(d.toDateString())) streak++;
      else if (i > 0) break;
    }

    res.json({
      success: true,
      stats: { totalSessions, weekSessions, todayCalories, totalExercises, streak },
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════════
   ROUTES — USER PROFILE  (protected)
═══════════════════════════════════════════════════════════════ */

// GET /api/profile
app.get('/api/profile', protect, async (req, res) => {
  res.json({
    success: true,
    user: { id: req.user._id, name: req.user.name, email: req.user.email, goal: req.user.goal, createdAt: req.user.createdAt },
  });
});

// PUT /api/profile
app.put('/api/profile', protect, async (req, res) => {
  try {
    const { name, goal } = req.body;
    const updated = await User.findByIdAndUpdate(
      req.user._id,
      { ...(name && { name }), ...(goal && { goal }) },
      { new: true, runValidators: true }
    ).select('-password');
    res.json({ success: true, message: 'Profile updated!', user: updated });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

// PUT /api/profile/password
app.put('/api/profile/password', protect, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user._id);
    if (!(await user.matchPassword(currentPassword)))
      return res.status(401).json({ success: false, message: 'Current password is incorrect.' });
    if (newPassword.length < 6)
      return res.status(400).json({ success: false, message: 'New password must be at least 6 characters.' });
    user.password = newPassword;
    await user.save();
    res.json({ success: true, message: 'Password updated successfully.' });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
});

/* ═══════════════════════════════════════════════════════════════
   SEED EXERCISES  (runs once if DB is empty)
═══════════════════════════════════════════════════════════════ */
const seedExercises = async () => {
  const count = await Exercise.countDocuments();
  if (count > 0) return;

  console.log('🌱  Seeding exercises...');
  await Exercise.insertMany([
    { name:'Push-Ups',       muscle:'Chest',     difficulty:'Beginner',     equipment:'Bodyweight', calories:8,  duration:'3 sets × 15 reps', description:'Classic push-up targeting chest, shoulders and triceps.',              color:'#00c8ff', animType:'ex-push',  emoji:'💪' },
    { name:'Barbell Squat',  muscle:'Legs',      difficulty:'Intermediate', equipment:'Barbell',    calories:15, duration:'4 sets × 8 reps',  description:'King of leg exercises. Targets quads, glutes and hamstrings.',          color:'#b0ff00', animType:'ex-squat', emoji:'🏋️' },
    { name:'Dumbbell Curl',  muscle:'Biceps',    difficulty:'Beginner',     equipment:'Dumbbells',  calories:6,  duration:'3 sets × 12 reps', description:'Isolation exercise for bicep peak development.',                        color:'#ff5f5f', animType:'ex-curl',  emoji:'💪' },
    { name:'Plank Hold',     muscle:'Core',      difficulty:'Beginner',     equipment:'Bodyweight', calories:5,  duration:'3 sets × 60 sec',  description:'Full core stabilization activating deep abdominal muscles.',            color:'#ffd93d', animType:'ex-plank', emoji:'🧘' },
    { name:'Box Jumps',      muscle:'Legs',      difficulty:'Advanced',     equipment:'Bodyweight', calories:18, duration:'4 sets × 10 reps', description:'Explosive plyometric for power, speed and athletic performance.',       color:'#b0ff00', animType:'ex-jump',  emoji:'⚡' },
    { name:'Cable Row',      muscle:'Back',      difficulty:'Intermediate', equipment:'Machines',   calories:10, duration:'4 sets × 10 reps', description:'Builds a thick, strong back with full range of motion.',               color:'#00c8ff', animType:'ex-row',   emoji:'🎯' },
    { name:'Overhead Press', muscle:'Shoulders', difficulty:'Intermediate', equipment:'Barbell',    calories:12, duration:'4 sets × 8 reps',  description:'Builds powerful shoulders and upper body pressing strength.',           color:'#c084fc', animType:'ex-push',  emoji:'🏋️' },
    { name:'Deadlift',       muscle:'Back',      difficulty:'Advanced',     equipment:'Barbell',    calories:20, duration:'4 sets × 5 reps',  description:'The ultimate full-body compound lift. Supreme strength builder.',      color:'#ff5f5f', animType:'ex-squat', emoji:'🔥' },
    { name:'Pull-Ups',       muscle:'Back',      difficulty:'Intermediate', equipment:'Bodyweight', calories:11, duration:'3 sets × 8 reps',  description:'Upper body pulling force that sculpts a wide V-taper back.',          color:'#b0ff00', animType:'ex-curl',  emoji:'💪' },
    { name:'Burpees',        muscle:'Full Body', difficulty:'Advanced',     equipment:'Bodyweight', calories:22, duration:'3 sets × 12 reps', description:'Total body cardio blast. Burns fat and builds endurance fast.',        color:'#ffd93d', animType:'ex-jump',  emoji:'⚡' },
    { name:'Tricep Dips',    muscle:'Triceps',   difficulty:'Beginner',     equipment:'Bodyweight', calories:7,  duration:'3 sets × 15 reps', description:'Effective tricep isolation using bodyweight resistance.',              color:'#00c8ff', animType:'ex-push',  emoji:'💪' },
    { name:'Leg Press',      muscle:'Legs',      difficulty:'Beginner',     equipment:'Machines',   calories:13, duration:'4 sets × 12 reps', description:'Safe compound leg movement for building quad strength.',              color:'#c084fc', animType:'ex-squat', emoji:'🏋️' },
  ]);
  console.log('✅  12 exercises seeded.');
};

mongoose.connection.once('open', seedExercises);

/* ═══════════════════════════════════════════════════════════════
   404 & ERROR HANDLER
═══════════════════════════════════════════════════════════════ */
app.use((req, res) => res.status(404).json({ success: false, message: `Route ${req.originalUrl} not found.` }));

app.use((err, req, res, next) => {
  console.error('💥 Server error:', err.message);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

/* ═══════════════════════════════════════════════════════════════
   START SERVER
═══════════════════════════════════════════════════════════════ */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`\n🚀  VirexFit API running on http://localhost:${PORT}`);
  console.log(`📖  Endpoints:`);
  console.log(`    POST   /api/auth/register`);
  console.log(`    POST   /api/auth/login`);
  console.log(`    GET    /api/auth/me`);
  console.log(`    GET    /api/exercises`);
  console.log(`    GET    /api/cart`);
  console.log(`    POST   /api/cart`);
  console.log(`    PATCH  /api/cart/:id`);
  console.log(`    DELETE /api/cart/:id`);
  console.log(`    PUT    /api/cart/reorder`);
  console.log(`    POST   /api/sessions`);
  console.log(`    GET    /api/sessions`);
  console.log(`    GET    /api/sessions/stats`);
  console.log(`    GET    /api/profile`);
  console.log(`    PUT    /api/profile`);
  console.log(`    PUT    /api/profile/password\n`);
});
