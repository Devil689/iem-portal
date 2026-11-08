# IEM Admission Portal - Express + PostgreSQL
Requirements: Node.js 18+, PostgreSQL 12+.

1. Create the database (SQL Shell / psql):   CREATE DATABASE iem_admission;
2. copy .env.example .env     then put your postgres password in DATABASE_URL
3. npm install
4. npm start                  (creates all tables + seed data automatically from schema.sql)
5. Open http://localhost:5000  (internet needed once: React loads from a CDN)

Admin login: choose "Admin" on login page -> username admin / password admin123
Tables: users, programs, applications, documents, payments, notifications.
Merit = 40% Class 10 + 60% Class 12 (generated column). Allocation = one SQL ROW_NUMBER() query.
