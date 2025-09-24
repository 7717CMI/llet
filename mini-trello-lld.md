# Mini Trello App - Low Level Design

**Project:** Kanban Board Application with Real-time Collaboration  
**Tech Stack:** MERN + Socket.io  
**Author:** [Your Name] - Software Developer  
**Date:** September 2025  

---

## 1. Database Design

### Entity Relationship Overview
```
┌─────────┐    owns     ┌────────────┐   contains   ┌──────┐   contains   ┌──────┐
│  User   │────────────→│ Workspace  │─────────────→│ List │─────────────→│ Card │
└─────────┘             └────────────┘              └──────┘              └──────┘
     │                        │                                              │
     │ member_of               │ tracks                                       │
     │                        ▼                                              │
     │                  ┌──────────┐                                         │
     │                  │ Activity │                                         │
     │                  └──────────┘                                         │
     │                                                                       │
     │ creates                                                               │
     └─────────────────────┐                                                 │
                           ▼                                                 │
                     ┌─────────┐           belongs_to                       │
                     │ Comment │←───────────────────────────────────────────┘
                     └─────────┘
```

### MongoDB Collections

#### **users**
```javascript
{
  _id: ObjectId,
  name: String (required, max: 50),
  email: String (unique, lowercase, required),
  password: String (hashed with bcrypt, min: 6),
  createdAt: Date (auto),
  updatedAt: Date (auto)
}

// Indexes
{ email: 1 } // unique, for login lookup
```

#### **workspaces**
```javascript
{
  _id: ObjectId,
  title: String (required),
  visibility: Enum ["private", "public"] (default: "private"),
  owner: ObjectId (ref: User, required),
  dueDate: Date (optional),
  members: [{
    user: ObjectId (ref: User),
    role: Enum ["admin", "member"] (default: "member"),
    invitedAt: Date (default: now),
    joinedAt: Date
  }],
  lists: [ObjectId] (ref: List, ordered array),
  createdAt: Date,
  updatedAt: Date
}

// Indexes for performance
{ "members.user": 1 },                    // find user workspaces
{ owner: 1 },                             // find owned workspaces  
{ visibility: 1 },                        // filter public workspaces
{ "members.user": 1, visibility: 1 },     // compound: user access + visibility
{ createdAt: -1 }                         // sort by newest first
```

#### **lists**
```javascript
{
  _id: ObjectId,
  title: String (required),
  workspaceId: ObjectId (ref: Workspace, required),
  position: Number (required, for ordering),
  cards: [ObjectId] (ref: Card),
  cardOrder: [ObjectId] (explicit order for drag-drop),
  createdAt: Date,
  updatedAt: Date
}

// Indexes
{ workspaceId: 1 },                       // lists in workspace
{ workspaceId: 1, position: 1 },          // ordered lists in workspace
{ position: 1 }                           // global position sorting
```

#### **cards**
```javascript
{
  _id: ObjectId,
  title: String (required),
  description: String (default: ""),
  listId: ObjectId (ref: List, required),
  workspaceId: ObjectId (ref: Workspace, required), // denormalized for fast queries
  position: Number (required),
  assignedTo: ObjectId (ref: User, optional),
  labels: [String] (array of label names),
  dueDate: Date (optional),
  createdAt: Date,
  updatedAt: Date
}

// Indexes for fast queries
{ listId: 1 },                            // cards in specific list
{ workspaceId: 1, listId: 1 },            // cards in list of workspace
{ workspaceId: 1, labels: 1 },            // filter by labels in workspace
{ title: "text", description: "text" },   // full-text search
{ position: 1 },                          // position-based sorting
{ assignedTo: 1 },                        // find user's assigned cards
{ dueDate: 1 }                            // sort by due date
```

#### **comments**
```javascript
{
  _id: ObjectId,
  cardId: ObjectId (ref: Card, required),
  workspaceId: ObjectId (ref: Workspace, required), // for access control
  userId: ObjectId (ref: User, required),
  content: String (required, trimmed),
  createdAt: Date (default: now),
  updatedAt: Date (updated on save)
}

// Indexes
{ cardId: 1 },                            // comments for card
{ workspaceId: 1 },                       // workspace comments
{ cardId: 1, createdAt: 1 },              // chronological comments per card
{ createdAt: -1 }                         // recent comments first
```

#### **activities**
```javascript
{
  _id: ObjectId,
  workspaceId: ObjectId (ref: Workspace, required),
  userId: ObjectId (ref: User, required),
  action: String (required), // "created card", "moved card", etc.
  timestamp: Date (required),
  metadata: Object (optional) // additional context
}

// Indexes
{ workspaceId: 1 },                       // workspace activity
{ userId: 1 },                            // user activity
{ workspaceId: 1, timestamp: -1 },        // recent workspace activity
{ timestamp: -1 }                         // global recent activity
```

### Data Consistency Strategy
- **Referential Integrity**: Use MongoDB references with populate
- **Denormalization**: Store `workspaceId` in cards for faster queries
- **Cascading Deletes**: Clean up related data when parent is deleted
- **Atomic Updates**: Use transactions for multi-document operations

---

## 2. API Endpoints

### Base URL: `http://localhost:5000/api`

#### Authentication Routes
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Create new user account | ❌ |
| POST | `/auth/login` | Authenticate user login | ❌ |
| GET | `/auth/me` | Get current user profile | ✅ |

#### Workspace Routes  
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/workspaces` | Get user's accessible workspaces | ✅ |
| POST | `/workspaces` | Create new workspace | ✅ |
| GET | `/workspaces/:id` | Get workspace with lists/cards | ✅ |
| PUT | `/workspaces/:id` | Update workspace details | ✅ |
| DELETE | `/workspaces/:id` | Delete workspace (owner only) | ✅ |
| POST | `/workspaces/:id/members` | Add member to workspace | ✅ |
| PUT | `/workspaces/:id/reorder-lists` | Reorder lists in workspace | ✅ |

#### List Routes
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/lists` | Create new list in workspace | ✅ |
| PUT | `/lists/:id` | Update list title | ✅ |
| DELETE | `/lists/:id` | Delete list and all cards | ✅ |
| PUT | `/lists/:id/reorder-cards` | Reorder cards within list | ✅ |

#### Card Routes
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/cards` | Create new card in list | ✅ |
| GET | `/cards/:id` | Get card details | ✅ |
| PUT | `/cards/:id` | Update card properties | ✅ |
| DELETE | `/cards/:id` | Delete card | ✅ |
| PUT | `/cards/:id/move` | Move card between lists | ✅ |

#### Comment & Search Routes
| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| GET | `/comments/card/:id` | Get all comments for card | ✅ |
| POST | `/comments` | Create new comment | ✅ |
| PUT | `/comments/:id` | Update comment | ✅ |
| DELETE | `/comments/:id` | Delete comment | ✅ |
| GET | `/search/workspace/:id` | Search cards in workspace | ✅ |
| GET | `/search/workspace/:id/labels` | Get available labels | ✅ |
| GET | `/activities/workspace/:id` | Get workspace activity log | ✅ |

### Sample API Requests & Responses

#### Login Request/Response
```javascript
// POST /api/auth/login
Request: {
  "email": "john@example.com",
  "password": "securepass123"
}

Response (200): {
  "message": "Login successful",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "user": {
    "id": "507f1f77bcf86cd799439011",
    "name": "John Doe",
    "email": "john@example.com"
  }
}
```

#### Create Card Request/Response
```javascript
// POST /api/cards
Headers: { "Authorization": "Bearer <token>" }
Request: {
  "title": "Fix login bug",
  "description": "Users can't login with special characters",
  "listId": "507f1f77bcf86cd799439015",
  "assignedTo": "507f1f77bcf86cd799439012",
  "labels": ["bug", "urgent"],
  "dueDate": "2025-10-15T00:00:00Z"
}

Response (201): {
  "message": "Card created successfully",
  "card": {
    "id": "507f1f77bcf86cd799439020",
    "title": "Fix login bug",
    "position": 3,
    "createdAt": "2025-09-24T10:30:00Z"
  }
}
```

#### Move Card Request
```javascript
// PUT /api/cards/:id/move
Request: {
  "targetListId": "507f1f77bcf86cd799439016",
  "newPosition": 2
}

Response (200): {
  "message": "Card moved successfully"
}
```

---

## 3. Main Components

### Backend Architecture

#### **File Structure**
```
backend/
├── models/
│   ├── User.js              // User schema with password hashing
│   ├── Workspace.js         // Workspace with members management
│   ├── List.js              // List with position ordering
│   ├── Card.js              // Card with full feature set
│   ├── Comment.js           // Comment system
│   └── Activity.js          // Activity logging
├── routes/
│   ├── auth.js              // Authentication endpoints
│   ├── workspaces.js        // Workspace CRUD + member management
│   ├── lists.js             // List operations
│   ├── cards.js             // Card operations + movement
│   ├── comments.js          // Comment CRUD
│   ├── search.js            // Search & filtering
│   └── activities.js        // Activity logs
├── middleware/
│   └── auth.js              // JWT token verification
├── config/
│   └── database.js          // MongoDB connection
└── index.js                 // Express server + Socket.io setup
```

#### **Key Backend Components**

**Authentication Middleware**
```javascript
const auth = async (req, res, next) => {
  try {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      return res.status(401).json({ message: 'Access denied - No token provided' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    
    if (!user) {
      return res.status(401).json({ message: 'Invalid token - User not found' });
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
};
```

**User Model with Password Hashing**
```javascript
const userSchema = new mongoose.Schema({
  name: { type: String, required: true, maxlength: 50, trim: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true, minlength: 6 }
}, { timestamps: true });

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

// Password comparison method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};
```

**Card Movement Logic**
```javascript
// PUT /api/cards/:id/move
const moveCard = async (req, res) => {
  try {
    const { cardId } = req.params;
    const { targetListId, newPosition } = req.body;

    const card = await Card.findById(cardId);
    const sourceListId = card.listId;

    // Update card's listId
    await Card.findByIdAndUpdate(cardId, { listId: targetListId, position: newPosition });

    // Update list card orders
    if (sourceListId.toString() !== targetListId) {
      // Remove from source list
      await List.findByIdAndUpdate(sourceListId, {
        $pull: { cards: cardId, cardOrder: cardId }
      });
      
      // Add to target list
      await List.findByIdAndUpdate(targetListId, {
        $push: { cards: cardId, cardOrder: { $each: [cardId], $position: newPosition } }
      });
    }

    // Emit real-time update
    const io = req.app.get('io');
    io.to(`workspace-${card.workspaceId}`).emit('card-moved', {
      cardId, sourceListId, targetListId, newPosition
    });

    res.json({ message: 'Card moved successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to move card' });
  }
};
```

### Frontend Architecture

#### **File Structure**
```
frontend/
├── src/
│   ├── components/
│   │   ├── auth/
│   │   │   ├── Login.jsx           // Login form with validation
│   │   │   ├── Register.jsx        // Registration form
│   │   │   └── ProtectedRoute.jsx  // Route authentication guard
│   │   ├── workspace/
│   │   │   ├── WorkspaceView.jsx   // Main kanban board
│   │   │   ├── CreateWorkspace.jsx // Workspace creation modal
│   │   │   └── WorkspaceCard.jsx   // Dashboard workspace preview
│   │   ├── board/
│   │   │   ├── List.jsx            // Kanban column component
│   │   │   ├── Card.jsx            // Task card with drag support
│   │   │   ├── CardModal.jsx       // Card detail/edit modal
│   │   │   └── DragDropContext.jsx // React DnD wrapper
│   │   ├── common/
│   │   │   ├── Header.jsx          // App navigation
│   │   │   ├── Loading.jsx         // Loading spinner component
│   │   │   └── ErrorBoundary.jsx   // Error fallback
│   │   └── Dashboard.jsx           // User workspace dashboard
│   ├── contexts/
│   │   ├── AuthContext.jsx         // Authentication state
│   │   ├── WorkspaceContext.jsx    // Workspace data management
│   │   └── SocketContext.jsx       // Real-time connection
│   ├── hooks/
│   │   ├── useApi.js               // Custom API calling hook
│   │   └── useDragDrop.js          // Drag and drop logic
│   └── utils/
│       ├── api.js                  // Axios configuration
│       └── constants.js            // App constants
```

#### **Key Frontend Components**

**AuthContext - State Management**
```javascript
const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [state, dispatch] = useReducer(authReducer, {
    user: null,
    token: localStorage.getItem('token'),
    isAuthenticated: false,
    loading: true,
    error: null
  });

  const login = async (credentials) => {
    dispatch({ type: 'AUTH_START' });
    try {
      const response = await axios.post('/api/auth/login', credentials);
      
      localStorage.setItem('token', response.data.token);
      axios.defaults.headers.common['Authorization'] = `Bearer ${response.data.token}`;
      
      dispatch({
        type: 'AUTH_SUCCESS',
        payload: { user: response.data.user, token: response.data.token }
      });
      
      return { success: true };
    } catch (error) {
      const message = error.response?.data?.message || 'Login failed';
      dispatch({ type: 'AUTH_FAILURE', payload: message });
      return { success: false, error: message };
    }
  };

  // Auto-load user on app start
  useEffect(() => {
    const loadUser = async () => {
      const token = localStorage.getItem('token');
      if (token) {
        try {
          axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
          const response = await axios.get('/api/auth/me');
          dispatch({
            type: 'AUTH_SUCCESS',
            payload: { user: response.data.user, token }
          });
        } catch (error) {
          localStorage.removeItem('token');
          dispatch({ type: 'AUTH_FAILURE', payload: 'Session expired' });
        }
      } else {
        dispatch({ type: 'AUTH_FAILURE', payload: null });
      }
    };
    
    loadUser();
  }, []);

  return (
    <AuthContext.Provider value={{ ...state, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
};
```

**Card Component with Drag Support**
```javascript
const Card = ({ card, listId, index }) => {
  const [isEditing, setIsEditing] = useState(false);
  const { socket } = useSocket();
  
  const handleCardUpdate = async (updatedData) => {
    try {
      await axios.put(`/api/cards/${card._id}`, updatedData);
      
      // Emit real-time update
      socket?.emit('card-updated', {
        cardId: card._id,
        listId,
        data: updatedData,
        workspaceId: card.workspaceId
      });
      
      setIsEditing(false);
    } catch (error) {
      console.error('Failed to update card:', error);
    }
  };

  return (
    <Draggable draggableId={card._id} index={index}>
      {(provided, snapshot) => (
        <div
          ref={provided.innerRef}
          {...provided.draggableProps}
          {...provided.dragHandleProps}
          className={`bg-white p-3 rounded-lg shadow-sm border ${
            snapshot.isDragging ? 'shadow-lg rotate-3' : ''
          }`}
        >
          {isEditing ? (
            <CardEditForm card={card} onSave={handleCardUpdate} onCancel={() => setIsEditing(false)} />
          ) : (
            <CardDisplay card={card} onEdit={() => setIsEditing(true)} />
          )}
        </div>
      )}
    </Draggable>
  );
};
```

---

## 4. Error Handling

### Error Response Standard
All API errors follow consistent format:
```javascript
{
  "message": "Human-readable error description",
  "errors": [           // Optional - for validation errors
    {
      "field": "email",
      "message": "Please enter a valid email address"
    }
  ],
  "code": "VALIDATION_ERROR"  // Optional - for client error handling
}
```

### HTTP Status Code Strategy
| Code | Category | Usage | Example Response |
|------|----------|--------|------------------|
| **200** | Success | Successful GET, PUT | `{ "data": {...} }` |
| **201** | Created | Successful POST | `{ "message": "Created successfully", "data": {...} }` |
| **400** | Bad Request | Validation failures | `{ "message": "Validation failed", "errors": [...] }` |
| **401** | Unauthorized | Missing/invalid auth | `{ "message": "Authentication required" }` |
| **403** | Forbidden | Permission denied | `{ "message": "Access denied - insufficient permissions" }` |
| **404** | Not Found | Resource missing | `{ "message": "Workspace not found" }` |
| **409** | Conflict | Duplicate resource | `{ "message": "Email already registered" }` |
| **422** | Unprocessable | Business logic error | `{ "message": "Cannot delete workspace with active members" }` |
| **500** | Server Error | Internal failures | `{ "message": "Internal server error" }` |

### Backend Error Handling Implementation

#### **Input Validation**
```javascript
// Route with validation middleware
router.post('/workspaces',
  [
    auth,
    body('title').trim().isLength({ min: 1, max: 100 }).withMessage('Title must be 1-100 characters'),
    body('visibility').optional().isIn(['private', 'public']).withMessage('Visibility must be private or public')
  ],
  async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        message: 'Validation failed',
        errors: errors.array(),
        code: 'VALIDATION_ERROR'
      });
    }
    
    // Process request...
  }
);
```

#### **Permission Checks**
```javascript
// Check workspace ownership
const workspace = await Workspace.findById(workspaceId);
if (!workspace) {
  return res.status(404).json({ 
    message: 'Workspace not found',
    code: 'RESOURCE_NOT_FOUND' 
  });
}

if (workspace.owner.toString() !== req.user.id) {
  return res.status(403).json({ 
    message: 'Only workspace owner can perform this action',
    code: 'INSUFFICIENT_PERMISSIONS' 
  });
}
```

#### **Database Error Handling**
```javascript
try {
  const user = await User.create({ name, email, password });
  res.status(201).json({ message: 'User created successfully', user });
} catch (error) {
  // Handle duplicate email (MongoDB unique constraint)
  if (error.code === 11000 && error.keyPattern.email) {
    return res.status(409).json({
      message: 'Email address already registered',
      code: 'DUPLICATE_EMAIL'
    });
  }
  
  console.error('Database error:', error);
  res.status(500).json({ 
    message: 'Failed to create user account',
    code: 'DATABASE_ERROR' 
  });
}
```

### Frontend Error Handling

#### **Global Error Context**
```javascript
const ErrorContext = createContext();

export const ErrorProvider = ({ children }) => {
  const [errors, setErrors] = useState([]);

  const addError = (error) => {
    const errorObj = {
      id: Date.now(),
      message: error.message || 'An unexpected error occurred',
      type: error.type || 'error',
      timestamp: new Date()
    };
    
    setErrors(prev => [...prev, errorObj]);
    
    // Auto-remove after 5 seconds
    setTimeout(() => removeError(errorObj.id), 5000);
  };

  const removeError = (id) => {
    setErrors(prev => prev.filter(error => error.id !== id));
  };

  return (
    <ErrorContext.Provider value={{ errors, addError, removeError }}>
      {children}
      <ErrorToast errors={errors} onClose={removeError} />
    </ErrorContext.Provider>
  );
};
```

#### **API Error Interceptor**
```javascript
// Axios response interceptor
axios.interceptors.response.use(
  (response) => response,
  (error) => {
    const { response } = error;
    
    // Handle authentication errors globally
    if (response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
      return Promise.reject(error);
    }
    
    // Format error for consistent handling
    const formattedError = {
      message: response?.data?.message || 'Network error occurred',
      status: response?.status,
      code: response?.data?.code,
      errors: response?.data?.errors || []
    };
    
    return Promise.reject(formattedError);
  }
);
```

#### **Component Error Boundaries**
```javascript
class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('Component Error:', error, errorInfo);
    // Could send to error reporting service here
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="min-h-screen flex items-center justify-center bg-gray-50">
          <div className="text-center">
            <h2 className="text-2xl font-bold text-gray-900 mb-4">
              Something went wrong
            </h2>
            <p className="text-gray-600 mb-6">
              Please refresh the page or try again later.
            </p>
            <button
              onClick={() => window.location.reload()}
              className="bg-blue-600 text-white px-4 py-2 rounded hover:bg-blue-700"
            >
              Refresh Page
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}
```

---

## 5. Real-time Communication

### Socket.io Architecture

#### **Server Configuration**
```javascript
const io = socketIo(server, {
  cors: {
    origin: process.env.CLIENT_URL || "http://localhost:5173",
    methods: ["GET", "POST"],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

// Authentication middleware for socket connections
io.use(async (socket, next) => {
  try {
    const token = socket.handshake.auth.token;
    if (!token) {
      return next(new Error('Authentication token required'));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('name email');
    
    if (!user) {
      return next(new Error('Invalid user'));
    }

    // Attach user info to socket
    socket.userId = user._id.toString();
    socket.userName = user.name;
    socket.userEmail = user.email;

    console.log(`Socket authenticated: ${user.name} (${socket.id})`);
    next();
  } catch (error) {
    console.error('Socket authentication failed:', error.message);
    next(new Error('Authentication failed'));
  }
});
```

#### **Real-time Event System**

| Event Category | Events | Purpose |
|----------------|--------|---------|
| **Workspace Management** | `join-workspace`, `leave-workspace` | User presence in workspaces |
| **User Presence** | `user-joined`, `user-left`, `user-list` | Track online users |
| **Cursor Sharing** | `cursor-move`, `cursor-hide` | Real-time cursor positions |
| **Content Updates** | `card-created`, `card-updated`, `card-deleted` | CRUD operations |
| **Movement** | `card-moved`, `list-reordered` | Drag and drop actions |
| **Collaboration** | `user-typing`, `comment-added` | Live collaboration indicators |

#### **Socket Connection Handling**
```javascript
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.userName} (${socket.id})`);

  // Join workspace room
  socket.on('join-workspace', async (workspaceId) => {
    try {
      // Verify user has access to workspace
      const workspace = await Workspace.findOne({
        _id: workspaceId,
        $or: [
          { 'members.user': socket.userId },
          { visibility: 'public' }
        ]
      });

      if (!workspace) {
        socket.emit('error', { message: 'Access denied to workspace' });
        return;
      }

      // Join room
      socket.join(`workspace-${workspaceId}`);
      socket.currentWorkspace = workspaceId;

      // Notify others
      socket.to(`workspace-${workspaceId}`).emit('user-joined', {
        userId: socket.userId,
        userName: socket.userName,
        socketId: socket.id,
        timestamp: new Date()
      });

      // Send current online users to new joiner
      const socketsInRoom = await io.in(`workspace-${workspaceId}`).fetchSockets();
      const onlineUsers = socketsInRoom.map(s => ({
        userId: s.userId,
        userName: s.userName,
        socketId: s.id
      }));

      socket.emit('user-list', onlineUsers);

      console.log(`${socket.userName} joined workspace ${workspaceId}`);
    } catch (error) {
      console.error('Join workspace error:', error);
      socket.emit('error', { message: 'Failed to join workspace' });
    }
  });

  // Leave workspace room
  socket.on('leave-workspace', (workspaceId) => {
    socket.leave(`workspace-${workspaceId}`);
    socket.currentWorkspace = null;

    socket.to(`workspace-${workspaceId}`).emit('user-left', {
      userId: socket.userId,
      userName: socket.userName,
      timestamp: new Date()
    });

    console.log(`${socket.userName} left workspace ${workspaceId}`);
  });

  // Real-time cursor movement
  socket.on('cursor-move', (data) => {
    if (!socket.currentWorkspace) return;

    socket.to(`workspace-${socket.currentWorkspace}`).emit('cursor-move', {
      userId: socket.userId,
      userName: socket.userName,
      x: data.x,
      y: data.y,
      timestamp: Date.now()
    });
  });

  // Card movement events
  socket.on('card-moved', (data) => {
    if (!socket.currentWorkspace) return;

    // Broadcast card movement to all users in workspace
    socket.to(`workspace-${socket.currentWorkspace}`).emit('card-moved', {
      ...data,
      userId: socket.userId,
      userName: socket.userName,
      timestamp: Date.now()
    });

    console.log(`${socket.userName} moved card ${data.cardId}`);
  });

  // Card content updates
  socket.on('card-updated', (data) => {
    if (!socket.currentWorkspace) return;

    socket.to(`workspace-${socket.currentWorkspace}`).emit('card-updated', {
      ...data,
      userId: socket.userId,
      userName: socket.userName,
      timestamp: Date.now()
    });
  });

  // List updates
  socket.on('list-updated', (data) => {
    if (!socket.currentWorkspace) return;

    socket.to(`workspace-${socket.currentWorkspace}`).emit('list-updated', {
      ...data,
      userId: socket.userId,
      userName: socket.userName,
      timestamp: Date.now()
    });
  });

  // Typing indicators for comments
  socket.on('user-typing', (data) => {
    if (!socket.currentWorkspace) return;

    socket.to(`workspace-${socket.currentWorkspace}`).emit('user-typing', {
      userId: socket.userId,
      userName: socket.userName,
      cardId: data.cardId,
      isTyping: data.isTyping
    });
  });

  // Handle disconnection
  socket.on('disconnect', (reason) => {
    console.log(`${socket.userName} disconnected: ${reason}`);
    
    // Notify workspace if user was in one
    if (socket.currentWorkspace) {
      socket.to(`workspace-${socket.currentWorkspace}`).emit('user-left', {
        userId: socket.userId,
        userName: socket.userName,
        reason: 'disconnected',
        timestamp: new Date()
      });
    }
  });

  // Error handling
  socket.on('error', (error) => {
    console.error(`Socket error for ${socket.userName}:`, error);
  });
});
```

### Frontend Socket Implementation

#### **SocketContext Provider**
```javascript
const SocketContext = createContext();

export const SocketProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [cursors, setCursors] = useState({});
  const { user, token, isAuthenticated } = useAuth();

  // Initialize socket connection
  useEffect(() => {
    if (isAuthenticated && user && token) {
      console.log('Initializing socket connection...');

      const newSocket = io(process.env.REACT_APP_SERVER_URL || 'http://localhost:5000', {
        auth: { token },
        transports: ['websocket', 'polling'],
        upgrade: true,
        rememberUpgrade: true
      });

      // Connection events
      newSocket.on('connect', () => {
        console.log('✅ Connected to server');
        setConnected(true);
      });

      newSocket.on('disconnect', (reason) => {
        console.log('❌ Disconnected:', reason);
        setConnected(false);
        setOnlineUsers([]);
        setCursors({});
      });

      newSocket.on('connect_error', (error) => {
        console.error('❌ Connection error:', error.message);
        setConnected(false);
      });

      // User presence events
      newSocket.on('user-joined', (data) => {
        console.log('👋 User joined:', data.userName);
        setOnlineUsers(prev => {
          const exists = prev.find(u => u.userId === data.userId);
          return exists ? prev : [...prev, data];
        });
      });

      newSocket.on('user-left', (data) => {
        console.log('👋 User left:', data.userName);
        setOnlineUsers(prev => prev.filter(u => u.userId !== data.userId));
        setCursors(prev => {
          const updated = { ...prev };
          delete updated[data.userId];
          return updated;
        });
      });

      newSocket.on('user-list', (users) => {
        console.log('👥 Online users:', users.length);
        setOnlineUsers(users);
      });

      // Cursor sharing
      newSocket.on('cursor-move', (data) => {
        setCursors(prev => ({
          ...prev,
          [data.userId]: {
            x: data.x,
            y: data.y,
            userName: data.userName,
            lastUpdate: data.timestamp
          }
        }));
      });

      setSocket(newSocket);

      return () => {
        console.log('🔌 Cleaning up socket connection');
        newSocket.disconnect();
        setSocket(null);
        setConnected(false);
        setOnlineUsers([]);
        setCursors({});
      };
    }
  }, [isAuthenticated, user?.id, token]);

  // Remove stale cursors
  useEffect(() => {
    const interval = setInterval(() => {
      const now = Date.now();
      setCursors(prev => {
        const updated = { ...prev };
        Object.keys(updated).forEach(userId => {
          if (now - updated[userId].lastUpdate > 3000) {
            delete updated[userId];
          }
        });
        return updated;
      });
    }, 1000);

    return () => clearInterval(interval);
  }, []);

  // Helper functions
  const joinWorkspace = (workspaceId) => {
    if (socket && connected) {
      socket.emit('join-workspace', workspaceId);
    }
  };

  const leaveWorkspace = (workspaceId) => {
    if (socket && connected) {
      socket.emit('leave-workspace', workspaceId);
    }
  };

  const emitCursorMove = throttle((x, y) => {
    if (socket && connected) {
      socket.emit('cursor-move', { x, y });
    }
  }, 50);

  const emitCardMoved = (data) => {
    if (socket && connected) {
      socket.emit('card-moved', data);
    }
  };

  const emitCardUpdated = (data) => {
    if (socket && connected) {
      socket.emit('card-updated', data);
    }
  };

  const emitTyping = (cardId, isTyping) => {
    if (socket && connected) {
      socket.emit('user-typing', { cardId, isTyping });
    }
  };

  const value = {
    socket,
    connected,
    onlineUsers,
    cursors,
    joinWorkspace,
    leaveWorkspace,
    emitCursorMove,
    emitCardMoved,
    emitCardUpdated,
    emitTyping
  };

  return (
    <SocketContext.Provider value={value}>
      {children}
    </SocketContext.Provider>
  );
};

export const useSocket = () => {
  const context = useContext(SocketContext);
  if (!context) {
    throw new Error('useSocket must be used within SocketProvider');
  }
  return context;
};
```

#### **Real-time Cursor Component**
```javascript
const CursorOverlay = () => {
  const { cursors } = useSocket();

  return (
    <div className="fixed inset-0 pointer-events-none z-50">
      {Object.entries(cursors).map(([userId, cursor]) => (
        <div
          key={userId}
          className="absolute transition-all duration-75 ease-out"
          style={{
            left: cursor.x,
            top: cursor.y,
            transform: 'translate(-2px, -2px)'
          }}
        >
          {/* Cursor pointer */}
          <svg
            width="20"
            height="20"
            viewBox="0 0 20 20"
            className="drop-shadow-md"
          >
            <path
              d="M0,0 L0,16 L6,12 L10,20 L12,19 L8,11 L16,11 Z"
              fill="#3B82F6"
              stroke="white"
              strokeWidth="1"
            />
          </svg>
          
          {/* User name label */}
          <div className="absolute top-5 left-2 bg-blue-600 text-white text-xs px-2 py-1 rounded shadow-lg whitespace-nowrap">
            {cursor.userName}
          </div>
        </div>
      ))}
    </div>
  );
};
```

#### **Drag and Drop with Real-time Sync**
```javascript
const useDragAndDrop = (workspaceId) => {
  const { emitCardMoved } = useSocket();
  const { updateLocalCard } = useWorkspace();

  const handleDragEnd = async (result) => {
    const { source, destination, draggableId } = result;

    // No destination or same position
    if (!destination || 
        (source.droppableId === destination.droppableId && 
         source.index === destination.index)) {
      return;
    }

    // Optimistic update for immediate UI feedback
    updateLocalCard(draggableId, {
      listId: destination.droppableId,
      position: destination.index
    });

    try {
      // Update server
      await axios.put(`/api/cards/${draggableId}/move`, {
        targetListId: destination.droppableId,
        newPosition: destination.index
      });

      // Emit to other users
      emitCardMoved({
        cardId: draggableId,
        sourceListId: source.droppableId,
        targetListId: destination.droppableId,
        sourceIndex: source.index,
        destinationIndex: destination.index,
        workspaceId
      });

    } catch (error) {
      console.error('Failed to move card:', error);
      // Revert optimistic update
      toast.error('Failed to move card. Refreshing...');
      window.location.reload();
    }
  };

  return { handleDragEnd };
};
```

### Performance Optimizations

#### **Event Throttling**
```javascript
// Throttle cursor movements to prevent spam
const throttle = (func, limit) => {
  let inThrottle;
  return function() {
    const args = arguments;
    const context = this;
    if (!inThrottle) {
      func.apply(context, args);
      inThrottle = true;
      setTimeout(() => inThrottle = false, limit);
    }
  };
};
```

#### **Connection Management**
```javascript
// Reconnection logic
const handleReconnect = () => {
  if (!connected && isAuthenticated) {
    console.log('🔄 Attempting to reconnect...');
    socket?.connect();
  }
};

// Heartbeat to detect disconnections
useEffect(() => {
  if (!socket) return;

  const interval = setInterval(() => {
    if (connected) {
      socket.emit('ping');
    }
  }, 25000);

  return () => clearInterval(interval);
}, [socket, connected]);
```

#### **Memory Management**
```javascript
// Clean up event listeners
useEffect(() => {
  if (!socket) return;

  const events = [
    'card-moved',
    'card-updated', 
    'list-updated',
    'user-typing'
  ];

  events.forEach(event => {
    socket.on(event, handleRealtimeUpdate);
  });

  return () => {
    events.forEach(event => {
      socket.off(event, handleRealtimeUpdate);
    });
  };
}, [socket]);
```

### Conflict Resolution Strategy

#### **Last Writer Wins**
- Server timestamps all operations
- Client conflicts resolved by server response
- UI reverts to server state on conflicts

#### **Optimistic Updates**
```javascript
const optimisticUpdate = (operation) => {
  // 1. Update UI immediately
  updateUI(operation);
  
  // 2. Send to server
  const promise = sendToServer(operation);
  
  // 3. Handle response
  promise
    .then(() => {
      // Success - emit to other users
      emitToOthers(operation);
    })
    .catch(() => {
      // Failed - revert UI
      revertUI(operation);
    });
};
```

---

## Summary

This Mini Trello application demonstrates a comprehensive full-stack solution with:

### **Architecture Highlights**
- **Scalable Database Design**: Optimized MongoDB schema with strategic indexing
- **RESTful API**: Complete CRUD operations with proper HTTP semantics  
- **Component-Based Frontend**: Modular React architecture with context state management
- **Comprehensive Error Handling**: Consistent error responses and user feedback
- **Real-time Collaboration**: WebSocket-based live updates with conflict resolution

### **Key Technical Features**
- **Authentication**: JWT-based security with token refresh
- **Data Consistency**: Referential integrity with optimistic updates
- **Performance**: Database indexing and query optimization
- **User Experience**: Drag-and-drop with real-time cursor sharing
- **Scalability**: Event-driven architecture with room-based broadcasting

### **Production Considerations**
- **Security**: Input validation, authentication middleware, CORS configuration
- **Error Handling**: Graceful degradation with user-friendly messages
- **Performance**: Connection pooling, event throttling, memory management
- **Monitoring**: Structured logging and error boundaries

This design provides a solid foundation for a production-ready collaborative kanban application with room for future enhancements like file attachments, advanced permissions, and mobile support.

---

## Quick Setup Guide

### **Prerequisites**
- Node.js 18+
- MongoDB 5.0+
- npm or yarn

### **Installation Steps**
```bash
# Clone repository
git clone <repository-url>
cd mini-trello-app

# Backend setup
cd backend
npm install
cp .env.example .env  # Configure environment variables
npm run dev

# Frontend setup (new terminal)
cd frontend  
npm install
npm run dev

# Access application
open http://localhost:5173
```

### **Environment Variables**
```env
# Backend (.env)
PORT=5000
MONGODB_URI=mongodb://localhost:27017/mini-trello
JWT_SECRET=your-super-secret-jwt-key-here
CLIENT_URL=http://localhost:5173

# Frontend (.env)
REACT_APP_SERVER_URL=http://localhost:5000
```

---

**Download Instructions:**
1. **Copy markdown content** from this artifact
2. **Save as** `Mini-Trello-LLD.md`
3. **Convert to PDF** using [Pandoc](https://pandoc.org/) or online tools
4. **For professional formatting**: Use Typora, Notion, or GitBook

---

*This LLD document provides comprehensive technical specifications for building a production-ready collaborative kanban application. Created with focus on clarity, completeness, and practical implementation guidance.*