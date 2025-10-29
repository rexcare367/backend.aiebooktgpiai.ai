# AWS Cognito Authentication - Usage Examples

## Quick Start Guide

This document provides practical examples for integrating AWS Cognito authentication in your application.

## 1. Frontend Integration Examples

### JavaScript/TypeScript Example

```javascript
// Configuration
const API_BASE_URL = 'http://localhost:8000';
const COGNITO_AUTH_BASE = `${API_BASE_URL}/api/user/auth/cognito`;

// 1. User Registration
async function registerUser(email, password, icNumber, phone) {
  try {
    const response = await fetch(`${COGNITO_AUTH_BASE}/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email,
        password: password,
        ic_number: icNumber,
        phone: phone
      })
    });
    
    const data = await response.json();
    
    if (data.success) {
      // Store tokens
      localStorage.setItem('jwt_token', data.token);
      localStorage.setItem('cognito_id_token', data.cognito_tokens.id_token);
      localStorage.setItem('cognito_access_token', data.cognito_tokens.access_token);
      localStorage.setItem('cognito_refresh_token', data.cognito_tokens.refresh_token);
      localStorage.setItem('user_id', data.user_id);
      
      console.log('Registration successful!', data);
      return data;
    } else {
      console.error('Registration failed:', data.message);
      throw new Error(data.message);
    }
  } catch (error) {
    console.error('Registration error:', error);
    throw error;
  }
}

// 2. User Login
async function loginUser(identifier, password) {
  try {
    const response = await fetch(`${COGNITO_AUTH_BASE}/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        identifier: identifier,  // Can be email or IC number
        password: password
      })
    });
    
    const data = await response.json();
    
    if (data.success) {
      // Store tokens
      localStorage.setItem('jwt_token', data.token);
      localStorage.setItem('cognito_id_token', data.cognito_tokens.id_token);
      localStorage.setItem('cognito_access_token', data.cognito_tokens.access_token);
      localStorage.setItem('cognito_refresh_token', data.cognito_tokens.refresh_token);
      localStorage.setItem('user_id', data.user_id);
      localStorage.setItem('user_data', JSON.stringify(data.data));
      
      console.log('Login successful!', data);
      return data;
    } else {
      console.error('Login failed:', data.message);
      throw new Error(data.message);
    }
  } catch (error) {
    console.error('Login error:', error);
    throw error;
  }
}

// 3. Forgot Password
async function forgotPassword(email) {
  try {
    const response = await fetch(`${COGNITO_AUTH_BASE}/forgot-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email
      })
    });
    
    const data = await response.json();
    
    if (data.success) {
      console.log('Reset code sent!', data);
      return data;
    } else {
      console.error('Forgot password failed:', data.message);
      throw new Error(data.message);
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    throw error;
  }
}

// 4. Reset Password
async function resetPassword(email, confirmationCode, newPassword) {
  try {
    const response = await fetch(`${COGNITO_AUTH_BASE}/reset-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: email,
        confirmation_code: confirmationCode,
        new_password: newPassword
      })
    });
    
    const data = await response.json();
    
    if (data.success) {
      console.log('Password reset successful!', data);
      return data;
    } else {
      console.error('Password reset failed:', data.message);
      throw new Error(data.message);
    }
  } catch (error) {
    console.error('Password reset error:', error);
    throw error;
  }
}

// 5. Get User Profile
async function getUserProfile() {
  try {
    const token = localStorage.getItem('jwt_token');
    
    if (!token) {
      throw new Error('No authentication token found');
    }
    
    const response = await fetch(`${COGNITO_AUTH_BASE}/profile`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`,
      }
    });
    
    const data = await response.json();
    
    if (data.success) {
      console.log('Profile retrieved!', data);
      return data.data;
    } else {
      console.error('Get profile failed:', data.message);
      throw new Error(data.message);
    }
  } catch (error) {
    console.error('Get profile error:', error);
    throw error;
  }
}

// 6. Logout
function logout() {
  localStorage.removeItem('jwt_token');
  localStorage.removeItem('cognito_id_token');
  localStorage.removeItem('cognito_access_token');
  localStorage.removeItem('cognito_refresh_token');
  localStorage.removeItem('user_id');
  localStorage.removeItem('user_data');
  console.log('Logged out successfully');
}

// 7. Check if user is authenticated
function isAuthenticated() {
  return localStorage.getItem('jwt_token') !== null;
}

// Example Usage:
/*
// Register
await registerUser('john@example.com', 'SecurePass123', '123456-12-1234', '+60123456789');

// Login
await loginUser('john@example.com', 'SecurePass123');

// Forgot Password
await forgotPassword('john@example.com');

// Reset Password (after receiving code via email)
await resetPassword('john@example.com', '123456', 'NewSecurePass123');

// Get Profile
const profile = await getUserProfile();

// Logout
logout();
*/
```

### React Example with Context

```javascript
import React, { createContext, useContext, useState, useEffect } from 'react';

const AuthContext = createContext();

export const useAuth = () => useContext(AuthContext);

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const API_BASE = 'http://localhost:8000/api/user/auth/cognito';

  useEffect(() => {
    // Check if user is logged in on mount
    const token = localStorage.getItem('jwt_token');
    const userData = localStorage.getItem('user_data');
    
    if (token && userData) {
      setUser(JSON.parse(userData));
    }
    setLoading(false);
  }, []);

  const register = async (email, password, icNumber, phone) => {
    const response = await fetch(`${API_BASE}/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, ic_number: icNumber, phone })
    });
    
    const data = await response.json();
    
    if (data.success) {
      localStorage.setItem('jwt_token', data.token);
      localStorage.setItem('user_data', JSON.stringify(data.data));
      setUser(data.data);
    }
    
    return data;
  };

  const login = async (identifier, password) => {
    const response = await fetch(`${API_BASE}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier, password })
    });
    
    const data = await response.json();
    
    if (data.success) {
      localStorage.setItem('jwt_token', data.token);
      localStorage.setItem('user_data', JSON.stringify(data.data));
      setUser(data.data);
    }
    
    return data;
  };

  const logout = () => {
    localStorage.removeItem('jwt_token');
    localStorage.removeItem('user_data');
    setUser(null);
  };

  const value = {
    user,
    loading,
    register,
    login,
    logout,
    isAuthenticated: !!user
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

// Usage in components:
/*
function LoginPage() {
  const { login } = useAuth();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  
  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const result = await login(email, password);
      if (result.success) {
        // Redirect to dashboard
      }
    } catch (error) {
      console.error(error);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <input value={email} onChange={(e) => setEmail(e.target.value)} />
      <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
      <button type="submit">Login</button>
    </form>
  );
}
*/
```

## 2. Python Client Example

```python
import requests

class CognitoAuthClient:
    def __init__(self, base_url='http://localhost:8000'):
        self.base_url = f"{base_url}/api/user/auth/cognito"
        self.token = None
        self.user_data = None
    
    def register(self, email, password, ic_number, phone):
        """Register a new user"""
        response = requests.post(
            f"{self.base_url}/signup",
            json={
                'email': email,
                'password': password,
                'ic_number': ic_number,
                'phone': phone
            }
        )
        data = response.json()
        
        if data['success']:
            self.token = data['token']
            self.user_data = data['data']
        
        return data
    
    def login(self, identifier, password):
        """Login user"""
        response = requests.post(
            f"{self.base_url}/login",
            json={
                'identifier': identifier,
                'password': password
            }
        )
        data = response.json()
        
        if data['success']:
            self.token = data['token']
            self.user_data = data['data']
        
        return data
    
    def forgot_password(self, email):
        """Request password reset"""
        response = requests.post(
            f"{self.base_url}/forgot-password",
            json={'email': email}
        )
        return response.json()
    
    def reset_password(self, email, confirmation_code, new_password):
        """Reset password with confirmation code"""
        response = requests.post(
            f"{self.base_url}/reset-password",
            json={
                'email': email,
                'confirmation_code': confirmation_code,
                'new_password': new_password
            }
        )
        return response.json()
    
    def get_profile(self):
        """Get user profile"""
        if not self.token:
            raise Exception("Not authenticated")
        
        response = requests.get(
            f"{self.base_url}/profile",
            headers={'Authorization': f'Bearer {self.token}'}
        )
        return response.json()
    
    def logout(self):
        """Logout user"""
        self.token = None
        self.user_data = None

# Usage Example:
if __name__ == "__main__":
    client = CognitoAuthClient()
    
    # Register
    result = client.register(
        email='test@example.com',
        password='SecurePass123',
        ic_number='123456-12-1234',
        phone='+60123456789'
    )
    print('Registration:', result)
    
    # Login
    result = client.login('test@example.com', 'SecurePass123')
    print('Login:', result)
    
    # Get Profile
    profile = client.get_profile()
    print('Profile:', profile)
    
    # Logout
    client.logout()
```

## 3. Mobile App Integration (Flutter Example)

```dart
import 'package:http/http.dart' as http;
import 'dart:convert';
import 'package:shared_preferences/shared_preferences.dart';

class CognitoAuthService {
  final String baseUrl = 'http://localhost:8000/api/user/auth/cognito';
  
  Future<Map<String, dynamic>> register({
    required String email,
    required String password,
    required String icNumber,
    required String phone,
  }) async {
    final response = await http.post(
      Uri.parse('$baseUrl/signup'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'email': email,
        'password': password,
        'ic_number': icNumber,
        'phone': phone,
      }),
    );
    
    final data = jsonDecode(response.body);
    
    if (data['success']) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('jwt_token', data['token']);
      await prefs.setString('user_data', jsonEncode(data['data']));
    }
    
    return data;
  }
  
  Future<Map<String, dynamic>> login({
    required String identifier,
    required String password,
  }) async {
    final response = await http.post(
      Uri.parse('$baseUrl/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({
        'identifier': identifier,
        'password': password,
      }),
    );
    
    final data = jsonDecode(response.body);
    
    if (data['success']) {
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('jwt_token', data['token']);
      await prefs.setString('user_data', jsonEncode(data['data']));
    }
    
    return data;
  }
  
  Future<Map<String, dynamic>> getProfile() async {
    final prefs = await SharedPreferences.getInstance();
    final token = prefs.getString('jwt_token');
    
    if (token == null) {
      throw Exception('Not authenticated');
    }
    
    final response = await http.get(
      Uri.parse('$baseUrl/profile'),
      headers: {'Authorization': 'Bearer $token'},
    );
    
    return jsonDecode(response.body);
  }
  
  Future<void> logout() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('jwt_token');
    await prefs.remove('user_data');
  }
}
```

## 4. Common Integration Patterns

### Protected Route Example (React)

```javascript
import { Navigate } from 'react-router-dom';
import { useAuth } from './AuthContext';

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useAuth();
  
  if (loading) {
    return <div>Loading...</div>;
  }
  
  if (!isAuthenticated) {
    return <Navigate to="/login" />;
  }
  
  return children;
}

// Usage:
<Route path="/dashboard" element={
  <ProtectedRoute>
    <Dashboard />
  </ProtectedRoute>
} />
```

### Axios Interceptor Example

```javascript
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api'
});

// Request interceptor to add token
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('jwt_token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response interceptor to handle 401
api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('jwt_token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export default api;
```

## 5. Error Handling Best Practices

```javascript
async function handleAuthOperation(operation) {
  try {
    const result = await operation();
    return { success: true, data: result };
  } catch (error) {
    // Network error
    if (!error.response) {
      return {
        success: false,
        message: 'Network error. Please check your connection.'
      };
    }
    
    // API error
    const status = error.response.status;
    const data = error.response.data;
    
    switch (status) {
      case 400:
        return { success: false, message: data.message || 'Invalid request' };
      case 401:
        return { success: false, message: 'Authentication failed' };
      case 404:
        return { success: false, message: 'User not found' };
      case 500:
        return { success: false, message: 'Server error. Please try again later.' };
      default:
        return { success: false, message: 'An unexpected error occurred' };
    }
  }
}
```

## 6. Testing Examples

### Jest Test Example

```javascript
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { AuthProvider } from './AuthContext';
import LoginPage from './LoginPage';

global.fetch = jest.fn();

describe('Login Flow', () => {
  beforeEach(() => {
    fetch.mockClear();
  });
  
  test('successful login', async () => {
    fetch.mockResolvedValueOnce({
      json: async () => ({
        success: true,
        token: 'mock-token',
        data: { email: 'test@example.com' }
      })
    });
    
    render(
      <AuthProvider>
        <LoginPage />
      </AuthProvider>
    );
    
    fireEvent.change(screen.getByLabelText(/email/i), {
      target: { value: 'test@example.com' }
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'password123' }
    });
    fireEvent.click(screen.getByText(/login/i));
    
    await waitFor(() => {
      expect(localStorage.getItem('jwt_token')).toBe('mock-token');
    });
  });
});
```

## Need Help?

- Check the main documentation: `COGNITO_AUTH_SETUP.md`
- Review API responses for detailed error messages
- Check browser console for client-side errors
- Review server logs for backend issues

