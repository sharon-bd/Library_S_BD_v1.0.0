# Python Project: Library Management System

To run the system, navigate to the `\backend` directory and execute the following command:

```
\backend>py app.py
```

The original database, located at `original_db\library.db`, contains dozens of books and customers. Developers can revert to it after running the test data creation script by copying it back into `backend\library.db`.

**Developed by**: Sharon Ben Dror  
**Email**: sharon_bd@walla.com

## Overview

This project is an academic project developed as part of a Full Stack Python course at John Bryce College, Tel Aviv, Israel. All customer data in this library system is fictitious, ensuring that no privacy concerns are violated.
The software was developed using various tools and technologies learned in the course, primarily using Flask as a server-side framework, alongside Python, JavaScript, HTML, CSS and others. The system defines the `return_date` (due date) for each loan based on the book's `type`, and upon actual return, it responds accordingly to the due date. Special design considerations are applied to visually distinguish books with a due date set for today, a future date, or a past date.

## Project Structure
The library management system follows a clean separation between frontend and backend components:

### Backend Key Structure
- `backend/` - Contains all server-side Python code
  - `app.py` - Main Flask application entry point with all routes and utility functions
  - `test_reset_db.py` - Test data generation script
  - `models/` - Database models and ORM definitions
  - `library.db` - SQLite database file
  - `logs/` - Directory for log files

### Frontend Structure
- `frontend/` - Contains all client-side code
  - `html/` - Core HTML pages
    - `homepage.html` - Main landing page
    - `books_list.html` - Book management interface
    - `customers_list.html` - Customer management interface
    - `loans.html` - Loan management interface
    - `developers.html` - Developer testing interface
    - `about.html` - Information about the library
    - `user_pages/` - Role-specific interfaces
    - `customer_dashboard.html` - Customer home page
    - `customer_books_list.html` - Books available to customers
    - `recommended_books.html` - Book recommendations for customers

This modular organization enables clear separation of concerns, making the codebase easier to navigate and maintain. The frontend communicates with the backend exclusively through the REST API, ensuring clean data flow and presentation logic separation.

## User Credentials

For testing and demonstration purposes, the following default credentials are provided for each user role. These are hardcoded into the system for this academic project and should be modified or secured in a production environment.

| Role                              | Username  | Password    |
| --------------------------------- | --------- | ----------- |
| Librarian                         | librarian | LibPass123  |
| Customer                          | customer  | CustPass456 |
| [Developer](#developer-interface) | developer | DevPass789  |

**Note**: Passwords are case-sensitive. Use these credentials to log in via the respective endpoints (`/login`, `/customer_login`, `/developer_login`).

## Project Requirements

### 1. Database Structure

- Books table with required fields: id (PK), title, author, year_published, type (1/2/3)
- Customers table with required fields: id (PK), name, city, age
- Loans table with required fields: id, cust_id, book_id, loan_date, return_date

### 2. Book Types and Loan Periods

- Type 1: Up to 10 days
- Type 2: Up to 5 days
- Type 3: Up to 2 days

The system uses Python's Enum class to define book types (BookType), providing a type-safe and self-documenting way to categorize books according to their loan periods, ensuring consistent application of business rules throughout the codebase.

The `return_date` (due date) is pre-determined based on the book's `type`. When a book is returned, the system evaluates the actual return date and responds accordingly (e.g., marking it as on-time, late, etc.).

### 3. REST API Architecture and User Interface

- Full REST API implementation on server side
- Client-server communication via JSON
- Static HTML pages with dynamic JavaScript updates
- Client-side rendering
- Real-time interface updates without page reloads
- Distinct visual styling for books based on their due date: today (current date), a future date, or a past date (overdue)

### 4. Core Technologies

- **Framework**: Flask
- **Database**: SQLAlchemy ORM with SQLite
- **Authentication**: JWT (JSON Web Tokens)
- **Frontend**: Bootstrap 5.3, JavaScript
- **Logging**: Advanced logging with `logging` and `coloredlogs`

### 5. Enhanced Features

1. **User Authentication System**

   - JWT-based authentication system
   - Different authorization levels: Librarian, Customer, Developer
   - Varying token expiration times based on user type
   - Protected route security
   - Error handling and unauthorized access prevention

2. **Soft Delete and Data Protection**

   - Records marked inactive instead of physical deletion
   - Prevention of customer deactivation with active loans
   - Prevention of loaned book deactivation
   - Data integrity preservation
   - Historical record maintenance

3. **Advanced User Experience**

   - Custom notifications using Toastify
   - Visual alerts for overdue loans
   - Book recommendations by categories
   - Smooth animations and transitions
   - Intuitive system-wide navigation
   - Deactivated books are not displayed to customers in the interface, ensuring an intuitive and clean user experience

4. ### <a id="developer-interface"></a>Developer Interface

   This section provides tools for developers to test and validate the functionality of the library system. It includes:

   - Multi-role login testing capabilities (e.g., simulating logins as Librarian, Customer, or Developer)
     - Test data generation tools and unit test frameworks (e.g., creating sample books, customers, and loans for testing automated validation)
   - Library system management interface (e.g., viewing system status and test results)

5. **Visual Feedback System**
   - Personalized Toastify notifications
   - Visual feedback for overdue loans
   - Interactive status indicators
   - Real-time update notifications

## Technologies

### Frontend

- HTML5, CSS3
- JavaScript (ES6+)
- Bootstrap 5.3
- jQuery 3.5.1
- Toastify-js (for notifications)

### Backend

- Python Flask
- SQLAlchemy ORM
- JWT Authentication
- Advanced Logging System

## API Endpoints

### Authentication

- `/login` - Librarian login
- `/customer_login` - Customer login
- `/developer_login` - Developer login

### Book Management

- `/api/books` - Book listing with filters
- `/add_book` - Add new books
- `/api/books/<book_id>` - Book details and history

### Customer Management

- `/api/customers` - Customer listing with filters
- `/add_customer` - Add new customers
- `/api/customers/<id>` - Customer details

### Loan Management

- `/loan_book` - Create new loan
- `/api/returnBook/<loan_id>` - Handle book returns
- `/late_loans` - List overdue loans

## Summary

The system provides complete library management functionality with role-based access control and proper error handling. The system also handles book titles containing apostrophes (e.g., "Harry's Adventure") gracefully, ensuring proper storage and display without errors.
The software is built modularly with clear separation between layers, enabling easy maintenance and future expansion.

© 2025 Sharon Ben Dror. All rights reserved.
