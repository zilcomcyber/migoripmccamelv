
# Comprehensive User Guide for Migori County Project Tracker

## Table of Contents
1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Public Interface](#public-interface)
4. [User Authentication](#user-authentication)
5. [Admin Dashboard](#admin-dashboard)
6. [Project Management](#project-management)
7. [Advanced Features](#advanced-features)
8. [Technical Reference](#technical-reference)
9. [Troubleshooting](#troubleshooting)
10. [API Documentation](#api-documentation)

---

## 1. Introduction

### 1.1 Welcome to Migori County Project Tracker

The Migori County Project Tracker is a comprehensive web-based platform designed to manage, track, and monitor development projects across Migori County. This system provides transparency and accountability by allowing both administrators and the public to view project progress, provide feedback, and stay informed about county developments.

### 1.2 System Overview

The platform serves multiple user types:
- **Public Users**: Can view published projects, submit feedback, and track progress
- **Admin Users**: Can manage projects, update statuses, and moderate content
- **Super Admins**: Have full system access including user management

### 1.3 Key Features

- **Project Management**: Create, edit, and track development projects
- **Progress Tracking**: Multi-step project workflows with status updates
- **Public Transparency**: Public-facing project display with filtering
- **Feedback System**: Community engagement through comments and feedback
- **Location-Based Filtering**: Filter projects by county, sub-county, and ward
- **Data Import/Export**: Bulk operations for project data
- **Mobile-Responsive Design**: Optimized for all device types

---

## 2. Getting Started

### 2.1 Accessing the Website

The Migori County Project Tracker is accessible through any modern web browser. Simply navigate to the website URL to begin exploring public projects.

**System Requirements:**
- Modern web browser (Chrome, Firefox, Safari, Edge)
- JavaScript enabled
- Internet connection
- No special plugins required

### 2.2 Homepage Overview

The homepage serves as the main entry point and features:

#### 2.2.1 Header Navigation
- **Logo**: Migori County branding with navigation menu toggle (for mobile)
- **Navigation Menu**: Links to different sections (visible when logged in)
- **Theme Toggle**: Switch between light and dark modes
- **Login Button**: Access to admin authentication

#### 2.2.2 Hero Section
- **Welcome Message**: Introduction to the platform
- **Quick Statistics**: Overview of total projects, ongoing initiatives, and completion rates
- **Call-to-Action Buttons**: Direct access to project listings and feedback submission

#### 2.2.3 Featured Content
- **Recent Projects**: Display of latest published projects
- **Progress Highlights**: Visual representation of project completion rates
- **Community Engagement**: Recent feedback and community interaction stats

### 2.3 Navigation Structure

The website follows a logical navigation structure:

```
Home
├── Projects (Public View)
│   ├── All Projects
│   ├── By Department
│   ├── By Location
│   └── By Status
├── Project Details
│   ├── Overview
│   ├── Steps & Progress
│   ├── Comments
│   └── Feedback
├── Admin Panel (Authenticated Users)
│   ├── Dashboard
│   ├── Project Management
│   ├── User Management
│   └── System Settings
└── Authentication
    ├── Login
    └── Logout
```

---

## 3. Public Interface

### 3.1 Project Browsing

#### 3.1.1 Project Listing Page

The main project listing provides a comprehensive view of all published projects:

**Filter Options:**
- **Department Filter**: Filter by government department (Health, Education, Infrastructure, etc.)
- **Location Filter**: Hierarchical filtering by County → Sub-County → Ward
- **Status Filter**: Filter by project status (Planning, Ongoing, Completed, Suspended)
- **Year Filter**: View projects by implementation year

**Sort Options:**
- Most Recent
- Alphabetical (A-Z)
- Progress Percentage
- Budget Amount

**Display Modes:**
- Grid View (default)
- List View
- Map View (if coordinates available)

#### 3.1.2 Project Cards

Each project is displayed as a card containing:

```
┌─────────────────────────────────────┐
│ [Project Image/Icon]                │
│ Project Name                        │
│ Department Badge                    │
│ Location: Ward, Sub-County          │
│ ████████░░ 80% Complete            │
│ Budget: KSH 2,500,000              │
│ Status: [Ongoing]                   │
│ [View Details Button]               │
└─────────────────────────────────────┘
```

### 3.2 Project Details Page

#### 3.2.1 Project Header
- **Project Title**: Full project name
- **Status Badge**: Current status with color coding
- **Location Information**: Complete address hierarchy
- **Progress Bar**: Visual progress indicator with percentage

#### 3.2.2 Project Information Grid
- **Department**: Implementing department
- **Budget**: Total allocated budget
- **Start Date**: Project commencement date
- **Expected End Date**: Projected completion date
- **Contractor**: Implementing contractor (if applicable)
- **Project Manager**: Contact person

#### 3.2.3 Project Description
Detailed narrative about:
- Project objectives
- Scope of work
- Expected outcomes
- Beneficiary information

#### 3.2.4 Project Steps & Timeline

Visual timeline showing:
```
Step 1: Planning & Approval     [✓] Completed
Step 2: Procurement            [●] In Progress
Step 3: Construction           [○] Pending
Step 4: Testing & Commission   [○] Pending
Step 5: Handover              [○] Pending
```

Each step includes:
- Step name and description
- Status indicator
- Start date
- Expected completion date
- Actual completion date (if finished)
- Notes and updates

### 3.3 Interactive Features

#### 3.3.1 Comment System

**Public Comments:**
- View approved comments from community members
- Reply to existing comments (nested conversations)
- Like/react to comments

**Comment Display:**
```
┌─────────────────────────────────────┐
│ 👤 John Doe • 2 days ago           │
│ Great to see this project moving   │
│ forward! When will the road be     │
│ accessible to traffic?             │
│                                    │
│ └─ 👤 Admin • 1 day ago           │
│    Expected completion by March    │
│    2024. Thank you for your       │
│    interest!                      │
│                                    │
│ 👍 12 likes • Reply               │
└─────────────────────────────────────┘
```

#### 3.3.2 Feedback Submission

**Feedback Form:**
- Project-specific feedback
- General suggestions
- Issue reporting
- Contact information (optional)

**Feedback Categories:**
- Positive feedback
- Concerns or issues
- Suggestions for improvement
- Questions about the project

### 3.4 Search Functionality

#### 3.4.1 Global Search
- Search across all project names
- Search in project descriptions
- Location-based search
- Real-time search suggestions

#### 3.4.2 Advanced Filtering
- Multiple criteria combination
- Date range selection
- Budget range filtering
- Custom saved filters

---

## 4. User Authentication

### 4.1 Admin Login System

#### 4.1.1 Login Process

**Access the Login Page:**
1. Click the "Login" button in the top-right corner
2. You'll be redirected to `/login.php`
3. Enter your credentials

**Login Form Fields:**
- **Username**: Your assigned administrator username
- **Password**: Secure password
- **Remember Me**: Optional checkbox for extended sessions

**Security Features:**
- CSRF protection tokens
- Session timeout protection
- Failed login attempt monitoring
- Secure password requirements

#### 4.1.2 User Roles and Permissions

**Super Admin:**
- Full system access
- User management
- System configuration
- All project operations

**Admin:**
- Project creation and editing
- Project step management
- Feedback moderation
- Limited user viewing

**Viewer:**
- Read-only access to admin panel
- View all projects and data
- Cannot modify any content

### 4.2 Session Management

#### 4.2.1 Session Security
- Automatic session timeout after inactivity
- Secure session token generation
- IP address validation
- Browser fingerprinting

#### 4.2.2 Logout Process
- Secure session destruction
- Automatic redirect to homepage
- Clear all authentication cookies

---

## 5. Admin Dashboard

### 5.1 Dashboard Overview

Upon successful login, administrators are presented with a comprehensive dashboard at `/admin/index.php`.

#### 5.1.1 Dashboard Layout

**Quick Actions Section (Top Priority):**
```
┌─────────────────────────────────────┐
│ ⚡ Quick Actions                    │
├─────────────────────────────────────┤
│ [📤 Import CSV] [➕ Add Project]    │
│ [👥 Manage Users] [📊 Reports]      │
│ [⚙️ Settings] [📋 Feedback]        │
└─────────────────────────────────────┘
```

**Recent Projects Section:**
- Latest 5 projects with quick edit access
- Progress indicators
- Status updates
- Direct management links

**Community Review Cards:**
- Recent feedback submissions
- Comments awaiting moderation
- Community engagement metrics

**Statistics Overview:**
- Total projects count
- Monthly project additions
- Completion rates
- Budget summaries

**System Overview (Bottom):**
- Server status
- Database health
- Recent admin activities
- System alerts

#### 5.1.2 Responsive Design

**Mobile View Adaptations:**
- Cards stack vertically
- 100% width utilization
- Reduced card heights
- Touch-friendly buttons
- Optimized spacing

**Tablet View:**
- 2-column card layout
- Medium-sized interactive elements
- Balanced spacing

### 5.2 Statistics and Analytics

#### 5.2.1 Project Statistics

**Current Month Metrics:**
- Projects created this month
- Projects completed this month
- Average completion time
- Budget utilization

**Overall Statistics:**
- Total projects in system
- Projects by status breakdown
- Department-wise distribution
- Location-wise distribution

#### 5.2.2 Performance Indicators

**Progress Tracking:**
```
Total Projects: 156
├── Completed: 89 (57%)
├── Ongoing: 45 (29%)
├── Planning: 18 (12%)
└── Suspended: 4 (2%)
```

**Monthly Trends:**
- Project creation trends
- Completion rate trends
- Budget allocation patterns
- User engagement metrics

---

## 6. Project Management

### 6.1 Creating Projects

#### 6.1.1 Multi-Step Project Creation

The project creation process uses a 4-step wizard at `/admin/create_project.php`:

**Step 1: Basic Information**
- Project Name (required)
- Project Description
- Department Selection
- Implementation Year
- Project Status
- Visibility Setting (Private/Published)

**Step 2: Location & Demographics**
- County Selection (auto-filled with Migori)
- Sub-County Selection
- Ward Selection
- Specific Location Description
- GPS Coordinates (optional)
- Beneficiary Count
- Target Demographics

**Step 3: Financial Information**
- Total Budget
- Budget Breakdown by category
- Funding Source
- Procurement Method
- Contractor Information
- Payment Schedule

**Step 4: Timeline & Steps**
- Project Start Date
- Expected Completion Date
- Milestone Definitions
- Default Project Steps
- Custom Step Addition
- Resource Allocation

#### 6.1.2 Project Step Templates

The system provides default step templates based on department:

**Infrastructure Projects:**
1. Planning & Design
2. Environmental Impact Assessment
3. Procurement & Contracting
4. Construction Phase
5. Quality Assurance
6. Commissioning & Handover

**Health Projects:**
1. Needs Assessment
2. Equipment Procurement
3. Staff Training
4. Implementation
5. Monitoring & Evaluation

**Education Projects:**
1. Infrastructure Development
2. Resource Procurement
3. Staff Deployment
4. Community Sensitization
5. Program Launch

### 6.2 Project Management Interface

#### 6.2.1 Project Listing (`/admin/projects.php`)

**List View Features:**
- Sortable columns
- Bulk operations
- Quick status updates
- Filter and search
- Export capabilities

**Available Columns:**
- Project Name
- Department
- Location
- Status
- Progress %
- Budget
- Created Date
- Actions

**Bulk Operations:**
- Status updates
- Visibility changes
- Export selected
- Delete multiple

#### 6.2.2 Individual Project Management (`/admin/manage_project.php`)

**Project Overview Section:**
- Complete project details
- Progress visualization
- Key metrics display
- Quick action buttons

**Visibility Control:**
```
┌─────────────────────────────────────┐
│ 🔒 Project Visibility              │
├─────────────────────────────────────┤
│ Current: [Private] ▼               │
│ Options:                           │
│ • Private (Admin Only)             │
│ • Published (Public)               │
│ [Update Visibility]                │
└─────────────────────────────────────┘
```

**Step Management:**
- Add new steps
- Edit existing steps
- Update step status
- Reorder steps
- Delete steps
- Add notes and updates

### 6.3 Step Management System

#### 6.3.1 Step Status Management

**Available Statuses:**
- **Pending**: Not yet started
- **In Progress**: Currently being worked on
- **Completed**: Finished successfully
- **Skipped**: Bypassed (with justification)

**Status Transitions:**
```
Pending → In Progress → Completed
    ↓           ↓
  Skipped ← Skipped
```

#### 6.3.2 Step Details

**Each Step Contains:**
- Step number (auto-assigned)
- Step name
- Detailed description
- Expected start date
- Expected end date
- Actual start date
- Actual completion date
- Status
- Notes and updates
- Responsible person/department

#### 6.3.3 Progress Calculation

The system automatically calculates project progress based on step completion:

```javascript
Progress = (Completed Steps / Total Steps) × 100
```

**Special Cases:**
- Skipped steps count as completed
- In-progress steps count as 50% complete
- Progress is rounded to nearest whole number

### 6.4 Project Editing

#### 6.4.1 Edit Project Form (`/admin/edit_project.php`)

**Editable Fields:**
- All basic information
- Location details
- Financial information
- Timeline adjustments
- Description updates

**Change Tracking:**
- All modifications are logged
- Previous values preserved
- Admin user attribution
- Timestamp recording

#### 6.4.2 Batch Operations

**CSV Import System (`/admin/import_csv.php`):**

**Supported File Format:**
```csv
project_name,department,sub_county,ward,budget,status,year,description
"New Hospital","Health","Migori","Central",2500000,"planning",2024,"Construction of new hospital facility"
```

**Import Process:**
1. Download CSV template
2. Fill with project data
3. Upload file (max 10MB)
4. Validate data
5. Review import summary
6. Confirm import

**Validation Rules:**
- Required fields checking
- Data type validation
- Location verification
- Budget format checking
- Department existence verification

---

## 7. Advanced Features

### 7.1 Feedback Management

#### 7.1.1 Feedback Dashboard (`/admin/feedback.php`)

**Feedback Categories:**
- Project-specific feedback
- General suggestions
- Bug reports
- Feature requests

**Management Actions:**
- View detailed feedback
- Mark as read/unread
- Respond to feedback
- Archive feedback
- Export feedback data

#### 7.1.2 Comment Moderation

**Comment Approval Workflow:**
1. User submits comment
2. Comment enters moderation queue
3. Admin reviews content
4. Admin approves/rejects
5. Approved comments appear publicly

**Moderation Criteria:**
- Appropriate language
- Relevant content
- No spam or promotional content
- Constructive feedback

### 7.2 User Management

#### 7.2.1 Admin User Management (`/admin/manage_admins.php`)

**User Operations:**
- Create new admin accounts
- Edit user permissions
- Change user roles
- Deactivate accounts
- Reset passwords

**User Information Fields:**
- Full name
- Username
- Email address
- Phone number
- Role assignment
- Department assignment
- Account status

#### 7.2.2 Role-Based Access Control

**Permission Matrix:**
```
Feature              | Super Admin | Admin | Viewer
--------------------|-------------|-------|--------
Create Projects     |     ✓       |   ✓   |   ✗
Edit All Projects   |     ✓       |   ✓   |   ✗
Delete Projects     |     ✓       |   ✓   |   ✗
Manage Users        |     ✓       |   ✗   |   ✗
System Settings     |     ✓       |   ✗   |   ✗
View Reports        |     ✓       |   ✓   |   ✓
Moderate Comments   |     ✓       |   ✓   |   ✗
```

### 7.3 Data Import/Export

#### 7.3.1 CSV Import Features

**Bulk Project Import:**
- Template-based import
- Data validation
- Error reporting
- Import summary
- Rollback capability

**Supported Data Fields:**
- Project basic information
- Location data
- Financial information
- Timeline data
- Step definitions

#### 7.3.2 Export Capabilities

**Available Export Formats:**
- CSV (Comma Separated Values)
- PDF Reports
- Excel Format (if PHPSpreadsheet available)

**Export Options:**
- All projects
- Filtered projects
- Date range exports
- Department-specific exports

### 7.4 System Configuration

#### 7.4.1 Application Settings

**Configurable Options:**
- Site name and branding
- Contact information
- Email settings
- File upload limits
- Session timeout values

#### 7.4.2 Database Management

**Maintenance Features:**
- Progress recalculation
- Data cleanup utilities
- Missing step generation
- Orphaned record cleanup

---

## 8. Technical Reference

### 8.1 System Architecture

#### 8.1.1 Technology Stack

**Frontend Technologies:**
- HTML5 with semantic markup
- CSS3 with modern features
- JavaScript (ES6+)
- Tailwind CSS framework
- Font Awesome icons
- Responsive design patterns

**Backend Technologies:**
- PHP 7.4+ 
- MySQL/MariaDB database
- PDO for database interactions
- Session-based authentication
- CSRF protection implementation

#### 8.1.2 File Structure

```
Project Root/
├── admin/                  # Admin panel files
│   ├── index.php          # Dashboard
│   ├── projects.php       # Project listing
│   ├── create_project.php # Project creation
│   ├── manage_project.php # Project management
│   └── ...
├── assets/                 # Static assets
│   ├── css/               # Stylesheets
│   ├── js/                # JavaScript files
│   └── index.php          # Security file
├── includes/               # PHP includes
│   ├── auth.php           # Authentication
│   ├── functions.php      # Utility functions
│   ├── header.php         # Page header
│   └── footer.php         # Page footer
├── api/                    # API endpoints
├── config.php              # Database configuration
├── index.php               # Homepage
└── project_details.php     # Project details
```

### 8.2 Database Schema

#### 8.2.1 Core Tables

**projects Table:**
```sql
CREATE TABLE projects (
    id INT PRIMARY KEY AUTO_INCREMENT,
    project_name VARCHAR(255) NOT NULL,
    description TEXT,
    department_id INT,
    sub_county_id INT,
    ward_id INT,
    status ENUM('planning', 'ongoing', 'completed', 'suspended'),
    budget DECIMAL(15,2),
    progress_percentage INT DEFAULT 0,
    visibility ENUM('private', 'published') DEFAULT 'private',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
```

**project_steps Table:**
```sql
CREATE TABLE project_steps (
    id INT PRIMARY KEY AUTO_INCREMENT,
    project_id INT,
    step_number INT,
    step_name VARCHAR(255) NOT NULL,
    description TEXT,
    status ENUM('pending', 'in_progress', 'completed', 'skipped'),
    start_date DATE,
    expected_end_date DATE,
    actual_end_date DATE,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

#### 8.2.2 Supporting Tables

**Location Tables:**
- counties
- sub_counties  
- wards
- departments

**User Management:**
- admin_users
- admin_sessions
- admin_activity_log

**Feedback System:**
- feedback
- project_comments

### 8.3 API Endpoints

#### 8.3.1 Public API

**Project Data API (`/api/projects.php`):**
- GET: Retrieve project list
- Supports filtering and pagination
- Returns JSON format

**Location API (`/api/locations.php`):**
- GET: Retrieve location hierarchies
- County/Sub-county/Ward relationships

#### 8.3.2 Admin API

**Dashboard Stats (`/api/dashboard_stats.php`):**
- Real-time statistics
- Chart data for analytics
- Performance metrics

**CSV Export (`/api/export_csv.php`):**
- Generate CSV files
- Custom field selection
- Filtered exports

### 8.4 Security Features

#### 8.4.1 Authentication Security

**Password Security:**
- Bcrypt hashing
- Minimum complexity requirements
- Password change enforcement
- Account lockout protection

**Session Security:**
- Secure session tokens
- HTTP-only cookies
- Session timeout
- Cross-device detection

#### 8.4.2 Input Validation

**Data Sanitization:**
- SQL injection prevention
- XSS attack protection
- CSRF token validation
- File upload security

**Access Control:**
- Role-based permissions
- Resource-level access control
- Action authorization
- Administrative privilege checks

---

## 9. User Interface Guide

### 9.1 Design System

#### 9.1.1 Color Scheme

**Light Theme:**
- Primary: Blue (#3B82F6)
- Secondary: Gray (#64748B)
- Success: Green (#10B981)
- Warning: Yellow (#F59E0B)
- Error: Red (#EF4444)

**Dark Theme:**
- Maintains same color relationships
- Adjusted for dark backgrounds
- Improved contrast ratios
- Reduced eye strain

#### 9.1.2 Typography

**Font Hierarchy:**
- Headings: Inter font family
- Body text: System font stack
- Code: Monospace fonts
- Icon font: Font Awesome

**Size Scale:**
- H1: 2.5rem (40px)
- H2: 2rem (32px)
- H3: 1.5rem (24px)
- Body: 1rem (16px)
- Small: 0.875rem (14px)

### 9.2 Interactive Elements

#### 9.2.1 Buttons

**Button Types:**
- Primary: Main actions (blue background)
- Secondary: Alternative actions (gray outline)
- Success: Positive actions (green background)
- Danger: Destructive actions (red background)

**Button States:**
- Normal: Default appearance
- Hover: Slightly darker shade
- Active: Pressed appearance
- Disabled: Reduced opacity

#### 9.2.2 Forms

**Form Controls:**
- Text inputs with focus states
- Select dropdowns with custom styling
- Checkboxes and radio buttons
- File upload areas
- Date pickers

**Validation:**
- Real-time validation
- Error message display
- Success confirmation
- Required field indicators

### 9.3 Responsive Behavior

#### 9.3.1 Breakpoints

**Device Targets:**
- Mobile: < 768px
- Tablet: 768px - 1024px
- Desktop: > 1024px
- Large screens: > 1440px

#### 9.3.2 Mobile Optimizations

**Navigation:**
- Collapsible mobile menu
- Touch-friendly buttons
- Swipe gestures support
- Optimized tap targets

**Content Layout:**
- Single column on mobile
- Stacked cards
- Full-width buttons
- Reduced margins/padding

---

## 10. Troubleshooting Guide

### 10.1 Common Issues

#### 10.1.1 Login Problems

**Issue: Cannot login with correct credentials**

*Possible Causes:*
- Expired session cookies
- Browser cache issues
- Database connection problems
- Account lockout

*Solutions:*
1. Clear browser cache and cookies
2. Try incognito/private browsing mode
3. Check if username and password are correct
4. Contact system administrator
5. Wait if account is temporarily locked

**Issue: Session expires too quickly**

*Solutions:*
- Check system session timeout settings
- Ensure browser accepts cookies
- Close other tabs using the same site
- Check for browser extensions blocking cookies

#### 10.1.2 Project Management Issues

**Issue: Cannot create new projects**

*Possible Causes:*
- Insufficient permissions
- Required fields missing
- Database connection issues
- Form validation errors

*Solutions:*
1. Verify user role and permissions
2. Fill all required fields (marked with *)
3. Check form validation messages
4. Try refreshing the page
5. Contact administrator if problem persists

**Issue: Project progress not updating**

*Solutions:*
1. Check if steps are being marked as completed
2. Refresh the project page
3. Verify step status updates are saved
4. Contact admin for progress recalculation

#### 10.1.3 File Upload Issues

**Issue: CSV import fails**

*Common Causes:*
- File size too large (>10MB)
- Incorrect file format
- Missing required columns
- Invalid data in cells

*Solutions:*
1. Check file size and compress if needed
2. Ensure file is in CSV format
3. Download and use the provided template
4. Validate data format before upload
5. Check for special characters in data

### 10.2 Performance Issues

#### 10.2.1 Slow Loading Times

**Page Load Optimization:**
- Clear browser cache
- Check internet connection speed
- Try accessing during off-peak hours
- Disable browser extensions temporarily

**Large Dataset Handling:**
- Use pagination on project lists
- Apply filters to reduce data load
- Export data in smaller chunks
- Contact admin for database optimization

#### 10.2.2 Mobile Performance

**Mobile-Specific Issues:**
- Ensure good cellular/WiFi signal
- Close unused browser tabs
- Restart browser application
- Clear mobile browser cache
- Update browser to latest version

### 10.3 Browser Compatibility

#### 10.3.1 Supported Browsers

**Fully Supported:**
- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

**Limited Support:**
- Internet Explorer 11 (basic functionality only)
- Older mobile browsers

#### 10.3.2 Feature Requirements

**Required Browser Features:**
- JavaScript enabled
- Cookies enabled
- Local storage support
- CSS3 support
- HTML5 form validation

---

## 11. API Documentation

### 11.1 Public API Endpoints

#### 11.1.1 Projects API

**Endpoint:** `GET /api/projects.php`

**Parameters:**
```json
{
  "limit": 10,
  "offset": 0,
  "department": "health",
  "status": "ongoing",
  "ward": "central",
  "year": 2024
}
```

**Response Format:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "project_name": "New Hospital Construction",
      "department_name": "Health",
      "status": "ongoing",
      "progress_percentage": 65,
      "budget": 2500000,
      "location": "Central Ward, Migori",
      "created_at": "2024-01-15"
    }
  ],
  "pagination": {
    "total": 156,
    "limit": 10,
    "offset": 0,
    "has_more": true
  }
}
```

#### 11.1.2 Location API

**Endpoint:** `GET /api/locations.php`

**Purpose:** Retrieve hierarchical location data

**Response:**
```json
{
  "success": true,
  "data": {
    "counties": [
      {
        "id": 1,
        "name": "Migori",
        "sub_counties": [
          {
            "id": 1,
            "name": "Migori",
            "wards": [
              {"id": 1, "name": "Central"},
              {"id": 2, "name": "East"}
            ]
          }
        ]
      }
    ]
  }
}
```

### 11.2 Admin API Endpoints

#### 11.2.1 Dashboard Statistics

**Endpoint:** `GET /api/dashboard_stats.php`

**Authentication:** Required

**Response:**
```json
{
  "success": true,
  "data": {
    "total_projects": 156,
    "ongoing_projects": 45,
    "completed_projects": 89,
    "this_month_projects": 12,
    "budget_summary": {
      "total_allocated": 450000000,
      "total_spent": 320000000
    },
    "recent_activities": [
      {
        "type": "project_created",
        "description": "New project 'School Renovation' created",
        "timestamp": "2024-01-20 10:30:00"
      }
    ]
  }
}
```

#### 11.2.2 CSV Export API

**Endpoint:** `POST /api/export_csv.php`

**Parameters:**
```json
{
  "fields": ["project_name", "department", "status", "budget"],
  "filters": {
    "status": "ongoing",
    "department": "health"
  },
  "format": "csv"
}
```

**Response:** 
- Content-Type: application/csv
- File download with filtered project data

---

## 12. System Administration

### 12.1 Database Management

#### 12.1.1 Regular Maintenance

**Daily Tasks:**
- Monitor system performance
- Check error logs
- Verify backup completion
- Review user activity

**Weekly Tasks:**
- Database optimization
- Clean up temporary files
- Review feedback submissions
- Update system statistics

**Monthly Tasks:**
- User account audit
- Performance review
- Security assessment
- Data archival

#### 12.1.2 Backup Procedures

**Automated Backups:**
- Daily database dumps
- File system snapshots
- Configuration backups
- Log file archival

**Recovery Procedures:**
- Point-in-time recovery
- Full system restoration
- Selective data recovery
- Disaster recovery protocols

### 12.2 Security Management

#### 12.2.1 User Account Security

**Password Policies:**
- Minimum 8 characters
- Mix of letters, numbers, symbols
- No dictionary words
- Regular password changes

**Account Monitoring:**
- Failed login attempts
- Unusual access patterns
- Privilege escalation attempts
- Data access auditing

#### 12.2.2 System Security

**Regular Security Tasks:**
- Software updates
- Security patch application
- Vulnerability scanning
- Access log review

**Security Monitoring:**
- Intrusion detection
- File integrity monitoring
- Database access logging
- Network traffic analysis

### 12.3 Performance Optimization

#### 12.3.1 Database Optimization

**Query Optimization:**
- Index management
- Query performance analysis
- Database structure optimization
- Data archival strategies

**Resource Management:**
- Memory allocation
- Connection pooling
- Cache configuration
- Load balancing

#### 12.3.2 Application Performance

**Frontend Optimization:**
- Asset minification
- Image optimization
- Browser caching
- CDN implementation

**Backend Optimization:**
- Code profiling
- Memory usage optimization
- Database query optimization
- Session management tuning

---

## 13. Customization Guide

### 13.1 Theming and Branding

#### 13.1.1 Color Customization

**CSS Variables:**
```css
:root {
  --primary-color: #3B82F6;
  --secondary-color: #64748B;
  --success-color: #10B981;
  --warning-color: #F59E0B;
  --error-color: #EF4444;
}
```

**Logo Replacement:**
- Replace logo files in assets directory
- Update header template references
- Maintain proper aspect ratios
- Optimize for different screen sizes

#### 13.1.2 Layout Customization

**Page Templates:**
- Header layout modification
- Footer content updates
- Navigation menu customization
- Color scheme adjustments

**Component Styling:**
- Button appearance
- Form styling
- Card layouts
- Typography settings

### 13.2 Feature Configuration

#### 13.2.1 Project Workflow Customization

**Step Templates:**
- Modify default project steps
- Create department-specific workflows
- Add custom validation rules
- Configure automated transitions

**Status Management:**
- Custom status definitions
- Status transition rules
- Notification triggers
- Approval workflows

#### 13.2.2 Reporting Customization

**Custom Reports:**
- Define new report types
- Create custom metrics
- Add visualization options
- Schedule automated reports

**Data Export:**
- Custom export formats
- Field selection options
- Filter presets
- Automated distribution

---

## 14. Integration Guide

### 14.1 Third-Party Integrations

#### 14.1.1 Email Integration

**SMTP Configuration:**
```php
// Email settings in config.php
define('SMTP_HOST', 'smtp.example.com');
define('SMTP_PORT', 587);
define('SMTP_USERNAME', 'username');
define('SMTP_PASSWORD', 'password');
define('SMTP_ENCRYPTION', 'tls');
```

**Email Features:**
- Notification emails
- Password reset emails
- Report distribution
- Alert notifications

#### 14.1.2 External APIs

**Government Data Integration:**
- Population statistics
- Geographic boundaries
- Budget allocations
- Development indicators

**Mapping Services:**
- Google Maps integration
- Location geocoding
- Route optimization
- Spatial analysis

### 14.2 Data Import/Export

#### 14.2.1 External System Integration

**ERP Integration:**
- Financial data synchronization
- Procurement information
- Resource allocation
- Progress reporting

**GIS Integration:**
- Spatial data import
- Mapping visualization
- Geographic analysis
- Location-based reporting

#### 14.2.2 Data Standards

**Import Formats:**
- CSV with standard headers
- JSON API format
- XML data exchange
- Excel spreadsheet support

**Export Formats:**
- Standardized CSV
- PDF reports
- JSON API responses
- Excel workbooks

---

## 15. Maintenance and Support

### 15.1 Routine Maintenance

#### 15.1.1 System Health Monitoring

**Performance Metrics:**
- Page load times
- Database query performance
- Server resource usage
- User session statistics

**Health Checks:**
- Database connectivity
- File system integrity
- External service availability
- Security certificate validity

#### 15.1.2 Data Maintenance

**Data Quality:**
- Duplicate record identification
- Data validation checks
- Orphaned record cleanup
- Reference integrity verification

**Archive Management:**
- Old project archival
- Log file rotation
- Backup verification
- Storage optimization

### 15.2 Support Procedures

#### 15.2.1 User Support

**Help Desk Process:**
1. Issue identification
2. Severity assessment
3. Initial troubleshooting
4. Escalation procedures
5. Resolution tracking

**Common Support Requests:**
- Password resets
- Access permission changes
- Data export requests
- Training assistance

#### 15.2.2 Technical Support

**Issue Categories:**
- System errors
- Performance problems
- Integration issues
- Security concerns

**Escalation Levels:**
- Level 1: Basic troubleshooting
- Level 2: Advanced technical issues
- Level 3: System architecture problems
- Level 4: Vendor support required

---

## 16. Future Enhancements

### 16.1 Planned Features

#### 16.1.1 Enhanced Analytics

**Advanced Reporting:**
- Real-time dashboards
- Predictive analytics
- Performance forecasting
- Resource optimization

**Data Visualization:**
- Interactive charts
- Geographic mapping
- Timeline visualization
- Comparison tools

#### 16.1.2 Mobile Application

**Native Mobile App:**
- Offline capability
- Push notifications
- Camera integration
- GPS tracking

**Progressive Web App:**
- Improved mobile experience
- Offline functionality
- App-like interface
- Background sync

### 16.2 Integration Roadmap

#### 16.2.1 Government Systems

**Financial Management:**
- Budget management systems
- Procurement platforms
- Payment processing
- Audit trail integration

**Planning Systems:**
- Development planning tools
- Resource allocation systems
- Performance management
- Strategic planning integration

#### 16.2.2 Citizen Engagement

**Public Participation:**
- Online consultations
- Feedback collection
- Voting mechanisms
- Community forums

**Transparency Tools:**
- Open data portals
- Public information access
- Real-time updates
- Social media integration

---

## 17. Appendices

### 17.1 Keyboard Shortcuts

**Navigation Shortcuts:**
- `Ctrl + /`: Global search
- `Alt + D`: Dashboard
- `Alt + P`: Projects
- `Alt + F`: Feedback
- `Escape`: Close modal/dropdown

**Editor Shortcuts:**
- `Ctrl + S`: Save form
- `Ctrl + Z`: Undo
- `Ctrl + Y`: Redo
- `Tab`: Next field
- `Shift + Tab`: Previous field

### 17.2 Error Codes

**Authentication Errors:**
- `AUTH001`: Invalid credentials
- `AUTH002`: Session expired
- `AUTH003`: Insufficient permissions
- `AUTH004`: Account locked

**Data Errors:**
- `DATA001`: Validation failed
- `DATA002`: Duplicate entry
- `DATA003`: Missing required field
- `DATA004`: Invalid format

**System Errors:**
- `SYS001`: Database connection failed
- `SYS002`: File upload error
- `SYS003`: Configuration error
- `SYS004`: External service unavailable

### 17.3 System Requirements

**Server Requirements:**
- PHP 7.4 or higher
- MySQL 5.7 or MariaDB 10.2+
- Apache 2.4 or Nginx 1.16+
- 512MB RAM minimum (2GB recommended)
- 1GB disk space minimum

**Client Requirements:**
- Modern web browser
- JavaScript enabled
- Cookies enabled
- Internet connection
- Screen resolution 320px+ width

### 17.4 Contact Information

**Technical Support:**
- Email: fbhamisike@gmail.com
- Phone: +254 702 353 585
- Email: stevekyle106@gmail.com
- Phone: +254 725 900 309
- Hours: Monday-Friday, 8:00 AM - 5:00 PM EAT

**System Administrator:**
- Email: admin@migoricounty.go.ke
- Emergency: +254 700 000 000

**Training and Documentation:**
- Email: fbhamisike@gmail.com
- Documentation updates: Check website regularly

---

## Conclusion

This comprehensive guide covers all aspects of the Migori County Project Tracker system. Whether you're a public user exploring projects, an administrator managing the system, or a technical user implementing customizations, this documentation provides the detailed information you need.

The system is designed to be intuitive and user-friendly while providing powerful tools for project management and community engagement. Regular updates to this documentation ensure it remains current with system enhancements and new features.

For additional support or clarification on any topic covered in this guide, please contact the support team using the information provided in the appendices.

**Document Version:** 1.0  
**Last Updated:** January 2024  
**Next Review Date:** July 2024


## Hidden Updates

v2 will have the following: 
1. project galery inside project details
2. admin pannel page for adding project images linked by project id/primary key.
3. add map management fo setlite mode, terrain view and trafic view. currently we are using terrain view.
4. mail comment responces to the respective owner. only admin replies are mailed.or, the user is alerted of having a reply on their comment.
5. on grid view, remove map and replace with an image of the project site or activity. a random image from the project galery.
6. a map link to the project location should be shown at the botom right coner of the project image. if a user clicks the map pin, they should be shown the full location of the project with meta data of the same project. For this, we shall have to create anow map file for locating the project. the map shall have the three map view types. that is setelite, terrein and trafic.
7. managing project steps ie reodering the steps. 
8. project status updates to flow automatically from all settings and updates.
9. change project links from using project id to a cleaner link that uses projec titles.
