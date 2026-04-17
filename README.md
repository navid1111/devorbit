# TurfMania

<div align="center">
  <img src="https://res.cloudinary.com/dzqgzquno/image/upload/hero_section_z44xkp.gif" alt="TurfMania Logo" width="600"/>
  <h3>Your Game, Your Turf, Your Time</h3>
  
  ![Express.js](https://img.shields.io/badge/Express.js-404D59?stycle=for-the-badge)
  ![TypeScript](https://img.shields.io/badge/TypeScript-007ACC?style=for-the-badge&logo=typescript&logoColor=white)
  ![Next.js](https://img.shields.io/badge/Next.js-000000?style=for-the-badge&logo=nextdotjs&logoColor=white)
  ![MongoDB](https://img.shields.io/badge/MongoDB-4EA94B?style=for-the-badge&logo=mongodb&logoColor=white)
  ![Docker](https://img.shields.io/badge/Docker-2CA5E0?style=for-the-badge&logo=docker&logoColor=white)
  ![Azure](https://img.shields.io/badge/Microsoft_Azure-0089D6?style=for-the-badge&logo=microsoft-azure&logoColor=white)
  ![Vercel](https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)
  ![Node.js](https://img.shields.io/badge/Node.js-339933?style=for-the-badge&logo=nodedotjs&logoColor=white)
</div>

## Overview

TurfMania is a comprehensive turf booking platform that connects sports enthusiasts with turf facilities. The application follows a modular architecture with separate interfaces for clients, organization owners, and administrators, creating a seamless experience for all stakeholders involved in the turf booking ecosystem.

## Live Demos

- **Client Portal:** [https://turfmania.vercel.app/](https://turfmania.vercel.app/)
- **Admin Dashboard:** [https://turfmania-admin.vercel.app/](https://turfmania-admin.vercel.app/)
- **Organization Portal:** [https://turfmania-organization.vercel.app/](https://turfmania-organization.vercel.app/)

## Features

### For Users
- **Explore Turfs**: Browse through available turf facilities with detailed information
- **Advanced Filtering**: Filter turfs based on location using Barikoi service integration
- **Review System**: Leave reviews and ratings for turfs after usage
- **Seamless Booking**: Book time slots with a user-friendly interface
- **Payment Integration**: Secure payment system with options for advance booking

### For Organizations
- **Onboarding Process**: Request to register your organization and turfs on our platform
- **Time Slot Management**: Robust time slot generator for effective scheduling
- **Team Management**: Add users to your organization with customized roles and permissions
- **Booking Oversight**: Track and manage all bookings for your turfs

### For Administrators
- **Request Processing**: Review and process organization registration requests
- **Role-Based Access Control**: Sophisticated user management system with customizable roles
- **Permission Management**: Create new roles and assign specific permissions
- **Platform Oversight**: Comprehensive dashboard to monitor platform activities
- **Automated Tasks**: Scheduled cronjobs for email notifications and database cleanup

## Tech Stack

### Backend
- **Framework**: Express.js with TypeScript
- **Database**: MongoDB (implied from structure)
- **Authentication**: JWT-based authentication
- **File Storage**: Cloudinary integration
- **Deployment**: Docker containerization on Azure App Service
- **Automation**: Scheduled cronjobs for emails and database maintenance

### Frontend
- **Framework**: Next.js
- **Styling**: (Tailwind CSS)
- **Deployment**: Vercel

## Project Structure

The project follows a monorepo structure with:

- **Server**: Express.js backend with a modular architecture
- **Client Portal**: Next.js frontend for end users
- **Admin Dashboard**: Next.js frontend for administrators
- **Organization Portal**: Next.js frontend for organization management

### Backend Module Structure
```
modules/
├── admin_actions/
├── auth/
├── booking/
├── facility/
├── health-metrics/
├── organization/
├── permission/
├── role/
├── search/
├── sports/
├── timeslot/
├── turf/
├── turf-review/
└── user/
```

Each module typically contains:
- **Controller**: Handles HTTP requests and responses
- **Model**: Defines data structure and database schema
- **Service**: Implements business logic
- **Routes**: Defines API endpoints

## Getting Started

### Prerequisites
- Node.js (v14+ recommended)
- npm or yarn
- MongoDB instance
- Cloudinary account (for media storage)

### Backend Setup
```bash
# Clone the repository
git clone https://github.com/whiteflags26/turfmania.git

# Navigate to server directory
cd turfmania/server

# Install dependencies
npm install

# Set up environment variables
# Create a .env file based on .env.example

# Start development server
npm run dev
```

### Frontend Setup
```bash
# Navigate to client, admin, or organization directory
cd turfmania/client  # or /admin or /organization

# Install dependencies
npm install

# Start development server
npm run dev
```

## Deployment

The application components are deployed as follows:
- **Backend**: Docker container on Azure App Service
- **Frontend Applications**: Vercel

## Development Workflow

Our team follows a structured git workflow:
![Git Workflow](https://res.cloudinary.com/dzqgzquno/image/upload/fl_preserve_transparency/v1746033750/WhatsApp_Image_2025-01-22_at_9.54.31_PM_ka9pgr.jpg?_s=public-apps)

## Documentation

Detailed documentation is available in our [docs folder](https://github.com/Learnathon-By-Geeky-Solutions/devorbit/tree/main/docs).

User flow diagrams are available [here](https://lucid.app/lucidchart/98e27590-5f93-4635-b14f-1c7a5847232d/edit?viewport_loc=-2086%2C-654%2C7994%2C3481%2C0_0&invitationId=inv_9c1d0b7d-1732-450f-af21-400bbee750ef).

## Team

- [Whiteflags26](https://github.com/whiteflags26)
- [Kashshaf-Labib](https://github.com/Kashshaf-Labib)
- [Navid1111](https://github.com/navid1111)

## License

[MIT License](LICENSE)