IT LABORATORY ASSET TRACKING SYSTEM - REVISED

This version is reorganized around the PDF requirements:
1. Hardware Inventory CRUD
2. Role-based User Login
3. Dashboard
4. Item Search & Filter
5. Borrowing Reports
6. Borrower Management
7. Return/overdue notifications
8. Profile Management
9. Activity Audit Logs
10. Inventory Export

ROLES
- staff: full system administration
- student_assistant: inventory/borrower/loan management and personal notifications
- instructor: inventory browsing, loan viewing, reports, profile and notifications

SETUP
1. Create/import backend/database/schema.sql in MySQL/phpMyAdmin.
2. Put the project folder inside C:\xampp\htdocs\.
3. Check connection.php if your MySQL credentials differ from root/no password.
4. Open /IT_Laboratory_Asset_Tracking_System_REVISED/login.php.

DEMO ACCOUNTS
- admin@itlab.com / password  (Laboratory Staff)
- assistant@itlab.com / password  (Student Assistant)
- instructor@itlab.com / password  (IT Instructor)

The project uses Bootstrap modals for add/edit forms, a collapsible mobile sidebar, CSRF tokens, prepared SQL statements, password hashing, role authorization, and audit logging.


MODAL FILES
The Bootstrap popup form markup is separated into the modals/ folder:
- modals/asset_modal.php
- modals/category_modal.php
- modals/borrower_modal.php
- modals/loan_modal.php
- modals/user_modal.php

The main index.php includes these modal partials. The models/ folder is retained for database/data logic (for example models/User.php); do not rename it to modals.
