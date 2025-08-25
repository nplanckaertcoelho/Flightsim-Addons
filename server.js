require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// Middleware
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('public'));

// MongoDB Connection
const connectDB = async () => {
    try {
        const conn = await mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/flightsim-addons', {
            useNewUrlParser: true,
            useUnifiedTopology: true,
        });

        console.log(`MongoDB Connected: ${conn.connection.host}`);
        await createDefaultUser();
        
    } catch (error) {
        console.error('Database connection error:', error);
        process.exit(1);
    }
};

// User Schema
const userSchema = new mongoose.Schema({
    username: {
        type: String,
        required: true,
        unique: true,
        trim: true
    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum: ['owner', 'admin'],
        default: 'owner'
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Hash password before saving
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (error) {
        next(error);
    }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Addon Schema
const versionSchema = new mongoose.Schema({
    version: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    downloadUrl: {
        type: String,
        required: true
    },
    size: String,
    changelog: String,
    latest: {
        type: Boolean,
        default: false
    }
});

const addonSchema = new mongoose.Schema({
    name: {
        type: String,
        required: true,
        trim: true
    },
    description: {
        type: String,
        required: true
    },
    author: {
        type: String,
        required: true,
        trim: true
    },
    simulator: {
        type: String,
        required: true,
        enum: ['msfs', 'xplane']
    },
    category: {
        type: String,
        required: true,
        enum: ['planes', 'scenery', 'utils']
    },
    versions: {
        type: [versionSchema],
        required: true,
        validate: {
            validator: function(v) {
                return v && v.length > 0;
            },
            message: 'At least one version is required'
        }
    },
    msfsVersion: String,
    xplaneVersion: String,
    thumbnail: String,
    rating: {
        type: Number,
        min: 1,
        max: 5
    },
    featured: {
        type: Boolean,
        default: false
    },
    isActive: {
        type: Boolean,
        default: true
    }
}, {
    timestamps: true
});

// Index for efficient queries
addonSchema.index({ simulator: 1, category: 1 });
addonSchema.index({ name: 'text', description: 'text', author: 'text' });

// Ensure only one version is marked as latest and at least one version exists
addonSchema.pre('save', function(next) {
    if (this.versions && this.versions.length > 0) {
        // Ensure only one version is marked as latest
        let latestFound = false;
        this.versions.forEach(version => {
            if (version.latest && !latestFound) {
                latestFound = true;
            } else if (version.latest && latestFound) {
                version.latest = false;
            }
        });
        
        // Validate that at least one version is marked as latest
        const hasLatest = this.versions.some(v => v.latest);
        if (!hasLatest) {
            return next(new Error('At least one version must be marked as latest'));
        }
    }
    next();
});

const Addon = mongoose.model('Addon', addonSchema);

// Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid or expired token' });
        }
        req.user = user;
        next();
    });
};

// Generate JWT token
const generateToken = (user) => {
    return jwt.sign(
        { 
            id: user._id,
            username: user.username, 
            role: user.role 
        },
        JWT_SECRET,
        { expiresIn: '24h' }
    );
};

// Create default user
const createDefaultUser = async () => {
    try {
        const userCount = await User.countDocuments();
        
        if (userCount === 0) {
            const defaultUser = new User({
                username: 'admin',
                password: 'password123',
                role: 'owner'
            });
            
            await defaultUser.save();
            console.log('Default admin user created: admin/password123');
        }
    } catch (error) {
        console.error('Error creating default user:', error);
    }
};

// ROUTES

// Login endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password required' });
        }

        // Find user
        const user = await User.findOne({ username, isActive: true });
        if (!user) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Generate token
        const token = generateToken(user);

        res.json({
            success: true,
            token: token,
            user: {
                id: user._id,
                username: user.username,
                role: user.role
            }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Verify token endpoint
app.get('/api/verify', authenticateToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// Get all addons (public endpoint)
app.get('/api/addons', async (req, res) => {
    try {
        const { simulator, category, search } = req.query;
        
        let filter = { isActive: true };
        
        if (simulator) {
            filter.simulator = simulator;
        }
        
        if (category) {
            filter.category = category;
        }
        
        if (search) {
            filter.$text = { $search: search };
        }

        const addons = await Addon.find(filter).sort({ createdAt: -1 });
        
        // Group by simulator and category for frontend compatibility
        const groupedAddons = {
            msfs: { planes: [], scenery: [], utils: [] },
            xplane: { planes: [], scenery: [], utils: [] }
        };
        
        addons.forEach(addon => {
            if (groupedAddons[addon.simulator] && groupedAddons[addon.simulator][addon.category]) {
                // Convert mongoose document to plain object and add id field
                const addonObj = addon.toObject();
                addonObj.id = addon._id.toString();
                groupedAddons[addon.simulator][addon.category].push(addonObj);
            }
        });

        res.json(groupedAddons);
    } catch (error) {
        console.error('Error fetching addons:', error);
        res.status(500).json({ error: 'Failed to load addons' });
    }
});

// Get single addon
app.get('/api/addons/:id', async (req, res) => {
    try {
        const addon = await Addon.findById(req.params.id);
        if (!addon || !addon.isActive) {
            return res.status(404).json({ error: 'Addon not found' });
        }
        
        const addonObj = addon.toObject();
        addonObj.id = addon._id.toString();
        res.json(addonObj);
    } catch (error) {
        console.error('Error fetching addon:', error);
        res.status(500).json({ error: 'Failed to load addon' });
    }
});

// Add new addon (owner only) - UPDATED FOR MULTIPLE VERSIONS
app.post('/api/addons', authenticateToken, async (req, res) => {
    try {
        const addonData = req.body;
        
        // Validate required fields
        const requiredFields = ['name', 'description', 'author', 'simulator', 'category'];
        for (const field of requiredFields) {
            if (!addonData[field]) {
                return res.status(400).json({ error: `${field} is required` });
            }
        }

        // Validate versions array
        if (!addonData.versions || !Array.isArray(addonData.versions) || addonData.versions.length === 0) {
            return res.status(400).json({ error: 'At least one version is required' });
        }

        // Validate each version
        for (const version of addonData.versions) {
            if (!version.version || !version.downloadUrl) {
                return res.status(400).json({ error: 'Each version must have a version number and download URL' });
            }
        }

        // Validate that at least one version is marked as latest
        const hasLatest = addonData.versions.some(v => v.latest);
        if (!hasLatest) {
            return res.status(400).json({ error: 'At least one version must be marked as latest' });
        }

        // Process versions
        const processedVersions = addonData.versions.map((version) => ({
            version: version.version,
            downloadUrl: version.downloadUrl,
            size: version.size || '',
            changelog: version.changelog || '',
            latest: version.latest || false,
            date: new Date()
        }));

        // Ensure only one version is marked as latest
        let latestCount = processedVersions.filter(v => v.latest).length;
        if (latestCount > 1) {
            // If multiple versions are marked as latest, only keep the first one
            let foundFirst = false;
            processedVersions.forEach(version => {
                if (version.latest && !foundFirst) {
                    foundFirst = true;
                } else if (version.latest && foundFirst) {
                    version.latest = false;
                }
            });
        }

        // Create addon object
        const addon = new Addon({
            name: addonData.name,
            description: addonData.description,
            author: addonData.author,
            simulator: addonData.simulator,
            category: addonData.category,
            versions: processedVersions,
            msfsVersion: addonData.msfsVersion || '',
            xplaneVersion: addonData.xplaneVersion || '',
            thumbnail: addonData.thumbnail || '',
            rating: addonData.rating || null,
            featured: addonData.featured || false
        });

        await addon.save();

        const addonObj = addon.toObject();
        addonObj.id = addon._id.toString();

        res.status(201).json({ success: true, addon: addonObj });
    } catch (error) {
        console.error('Error creating addon:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to create addon' });
    }
});

// Update addon (owner only)
app.put('/api/addons/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const updateData = req.body;
        
        const addon = await Addon.findById(id);
        if (!addon) {
            return res.status(404).json({ error: 'Addon not found' });
        }

        // If versions are being updated, process them
        if (updateData.versions && Array.isArray(updateData.versions)) {
            // Validate each version
            for (const version of updateData.versions) {
                if (!version.version || !version.downloadUrl) {
                    return res.status(400).json({ error: 'Each version must have a version number and download URL' });
                }
            }

            // Validate that at least one version is marked as latest
            const hasLatest = updateData.versions.some(v => v.latest);
            if (!hasLatest) {
                return res.status(400).json({ error: 'At least one version must be marked as latest' });
            }

            // Process versions
            updateData.versions = updateData.versions.map((version) => ({
                version: version.version,
                downloadUrl: version.downloadUrl,
                size: version.size || '',
                changelog: version.changelog || '',
                latest: version.latest || false,
                date: version.date || new Date()
            }));

            // Ensure only one version is marked as latest
            let latestCount = updateData.versions.filter(v => v.latest).length;
            if (latestCount > 1) {
                let foundFirst = false;
                updateData.versions.forEach(version => {
                    if (version.latest && !foundFirst) {
                        foundFirst = true;
                    } else if (version.latest && foundFirst) {
                        version.latest = false;
                    }
                });
            }
        }

        // Update addon
        Object.assign(addon, updateData);
        await addon.save();

        const addonObj = addon.toObject();
        addonObj.id = addon._id.toString();

        res.json({ success: true, addon: addonObj });
    } catch (error) {
        console.error('Error updating addon:', error);
        if (error.name === 'ValidationError') {
            return res.status(400).json({ error: error.message });
        }
        res.status(500).json({ error: 'Failed to update addon' });
    }
});

// Delete addon (owner only)
app.delete('/api/addons/:id', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        const addon = await Addon.findById(id);
        if (!addon) {
            return res.status(404).json({ error: 'Addon not found' });
        }

        // Soft delete
        addon.isActive = false;
        await addon.save();

        res.json({ success: true, message: 'Addon deleted successfully' });
    } catch (error) {
        console.error('Error deleting addon:', error);
        res.status(500).json({ error: 'Failed to delete addon' });
    }
});

// Add version to existing addon (owner only)
app.post('/api/addons/:id/versions', authenticateToken, async (req, res) => {
    try {
        const { id } = req.params;
        const versionData = req.body;
        
        // Validate version data
        if (!versionData.version || !versionData.downloadUrl) {
            return res.status(400).json({ error: 'Version number and download URL are required' });
        }

        const addon = await Addon.findById(id);
        if (!addon) {
            return res.status(404).json({ error: 'Addon not found' });
        }

        // Check if version already exists
        const existingVersion = addon.versions.find(v => v.version === versionData.version);
        if (existingVersion) {
            return res.status(400).json({ error: 'Version already exists' });
        }

        // Create new version
        const newVersion = {
            version: versionData.version,
            downloadUrl: versionData.downloadUrl,
            size: versionData.size || '',
            changelog: versionData.changelog || '',
            latest: versionData.latest || false,
            date: new Date()
        };

        // If this version is marked as latest, unmark others
        if (newVersion.latest) {
            addon.versions.forEach(v => v.latest = false);
        }

        addon.versions.push(newVersion);
        await addon.save();

        const addonObj = addon.toObject();
        addonObj.id = addon._id.toString();

        res.json({ success: true, addon: addonObj });
    } catch (error) {
        console.error('Error adding version:', error);
        res.status(500).json({ error: 'Failed to add version' });
    }
});

// Update specific version (owner only)
app.put('/api/addons/:id/versions/:versionId', authenticateToken, async (req, res) => {
    try {
        const { id, versionId } = req.params;
        const updateData = req.body;
        
        const addon = await Addon.findById(id);
        if (!addon) {
            return res.status(404).json({ error: 'Addon not found' });
        }

        const version = addon.versions.id(versionId);
        if (!version) {
            return res.status(404).json({ error: 'Version not found' });
        }

        // Update version fields
        if (updateData.version) version.version = updateData.version;
        if (updateData.downloadUrl) version.downloadUrl = updateData.downloadUrl;
        if (updateData.size !== undefined) version.size = updateData.size;
        if (updateData.changelog !== undefined) version.changelog = updateData.changelog;
        
        // Handle latest flag
        if (updateData.latest !== undefined) {
            if (updateData.latest) {
                // If setting this version as latest, unmark others
                addon.versions.forEach(v => v.latest = false);
                version.latest = true;
            } else {
                version.latest = false;
                // Ensure at least one version is marked as latest
                const hasLatest = addon.versions.some(v => v.latest);
                if (!hasLatest && addon.versions.length > 0) {
                    return res.status(400).json({ error: 'At least one version must be marked as latest' });
                }
            }
        }

        await addon.save();

        const addonObj = addon.toObject();
        addonObj.id = addon._id.toString();

        res.json({ success: true, addon: addonObj });
    } catch (error) {
        console.error('Error updating version:', error);
        res.status(500).json({ error: 'Failed to update version' });
    }
});

// Delete specific version (owner only)
app.delete('/api/addons/:id/versions/:versionId', authenticateToken, async (req, res) => {
    try {
        const { id, versionId } = req.params;
        
        const addon = await Addon.findById(id);
        if (!addon) {
            return res.status(404).json({ error: 'Addon not found' });
        }

        if (addon.versions.length <= 1) {
            return res.status(400).json({ error: 'Cannot delete the last version' });
        }

        const versionIndex = addon.versions.findIndex(v => v._id.toString() === versionId);
        if (versionIndex === -1) {
            return res.status(404).json({ error: 'Version not found' });
        }

        const wasLatest = addon.versions[versionIndex].latest;
        addon.versions.splice(versionIndex, 1);

        // If we deleted the latest version, ensure there's still one latest version
        if (wasLatest) {
            const hasLatest = addon.versions.some(v => v.latest);
            if (!hasLatest && addon.versions.length > 0) {
                addon.versions[0].latest = true;
            }
        }

        await addon.save();

        const addonObj = addon.toObject();
        addonObj.id = addon._id.toString();

        res.json({ success: true, addon: addonObj });
    } catch (error) {
        console.error('Error deleting version:', error);
        res.status(500).json({ error: 'Failed to delete version' });
    }
});

// Get addon statistics (owner only)
app.get('/api/stats', authenticateToken, async (req, res) => {
    try {
        const totalAddons = await Addon.countDocuments({ isActive: true });
        const msfsAddons = await Addon.countDocuments({ simulator: 'msfs', isActive: true });
        const xplaneAddons = await Addon.countDocuments({ simulator: 'xplane', isActive: true });
        const featuredAddons = await Addon.countDocuments({ featured: true, isActive: true });

        const categoryStats = await Addon.aggregate([
            { $match: { isActive: true } },
            { $group: { _id: '$category', count: { $sum: 1 } } }
        ]);

        const versionStats = await Addon.aggregate([
            { $match: { isActive: true } },
            { $project: { versionCount: { $size: '$versions' } } },
            { $group: { _id: null, totalVersions: { $sum: '$versionCount' }, avgVersions: { $avg: '$versionCount' } } }
        ]);

        res.json({
            total: totalAddons,
            msfs: msfsAddons,
            xplane: xplaneAddons,
            featured: featuredAddons,
            categories: categoryStats.reduce((acc, cat) => {
                acc[cat._id] = cat.count;
                return acc;
            }, {}),
            versions: versionStats[0] || { totalVersions: 0, avgVersions: 0 }
        });
    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ error: 'Failed to load statistics' });
    }
});

// Search addons (public endpoint)
app.get('/api/search', async (req, res) => {
    try {
        const { q, simulator, category, limit = 20 } = req.query;
        
        let filter = { isActive: true };
        
        if (simulator) {
            filter.simulator = simulator;
        }
        
        if (category) {
            filter.category = category;
        }
        
        if (q) {
            filter.$text = { $search: q };
        }

        const addons = await Addon.find(filter)
            .limit(parseInt(limit))
            .sort(q ? { score: { $meta: 'textScore' } } : { createdAt: -1 });
        
        const results = addons.map(addon => {
            const addonObj = addon.toObject();
            addonObj.id = addon._id.toString();
            return addonObj;
        });

        res.json({ results, total: results.length });
    } catch (error) {
        console.error('Error searching addons:', error);
        res.status(500).json({ error: 'Search failed' });
    }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'OK', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        version: '1.0.0'
    });
});

// Get server info
app.get('/api/info', (req, res) => {
    res.json({
        name: 'FlightSim Addon Manager API',
        version: '1.0.0',
        description: 'Backend API for managing flight simulator addons',
        endpoints: {
            auth: ['/api/login', '/api/verify'],
            addons: ['/api/addons', '/api/addons/:id', '/api/search'],
            versions: ['/api/addons/:id/versions', '/api/addons/:id/versions/:versionId'],
            stats: ['/api/stats'],
            health: ['/api/health', '/api/info']
        }
    });
});

// Serve the frontend (put this after all API routes)
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/public/index.html');
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? error.message : 'Something went wrong'
    });
});

// Handle 404 for API routes
app.use('/api/', (req, res) => {
    res.status(404).json({ error: 'API endpoint not found' });
});

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\nShutting down gracefully...');
    try {
        await mongoose.connection.close();
        console.log('MongoDB connection closed.');
        process.exit(0);
    } catch (error) {
        console.error('Error during shutdown:', error);
        process.exit(1);
    }
});

// Start server
const startServer = async () => {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`🚀 Server running on port ${PORT}`);
            console.log(`📱 Environment: ${process.env.NODE_ENV || 'development'}`);
            console.log(`🔗 API Base URL: http://localhost:${PORT}/api`);
            console.log(`🌐 Frontend URL: http://localhost:${PORT}`);
            console.log('📊 Available endpoints:');
            console.log('   - GET  /api/health        - Health check');
            console.log('   - GET  /api/info          - API information');
            console.log('   - POST /api/login         - User authentication');
            console.log('   - GET  /api/addons        - Get all addons');
            console.log('   - POST /api/addons        - Create addon (auth required)');
            console.log('   - GET  /api/search        - Search addons');
            console.log('   - GET  /api/stats         - Get statistics (auth required)');
        });
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
};

startServer();

module.exports = app;