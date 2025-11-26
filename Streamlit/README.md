# CQMS – Client Query Management System

Streamlit-based application for managing client support queries.

## Overview
CQMS allows Clients to raise queries and Support users to manage them. It includes authentication, query submission, query listing, filtering, and closing functionalities.

## Features
- User Registration & Login (Client / Support)
- SHA-256 Password Hashing
- Query Submission with Auto-generated IDs
- Support-side Query Filtering (Status, Category)
- Query Closure
- MySQL Database Integration

## Requirements
Install dependencies:
```
pip install streamlit pandas numpy matplotlib mysql-connector-python
```

## Database
Create database:
```
CREATE DATABASE cqms;
```

Create tables:
```
CREATE TABLE cqms.registered_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    hashed_password VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL
);
```

```
CREATE TABLE cqms.client_queries (
    Id INT AUTO_INCREMENT PRIMARY KEY,
    query_id VARCHAR(20),
    client_email VARCHAR(255),
    client_mobile BIGINT,
    query_heading VARCHAR(255),
    query_description TEXT,
    status VARCHAR(20),
    date_created DATETIME,
    date_closed DATETIME
);
```

## Secrets Configuration
```
[mysql]
host = "localhost"
user = "root"
password = "your_password"
database = "cqms"
```

## Run Application
```
streamlit run cqms.py
```

## Future Enhancements
- Admin Panel
- Notifications
- Attachments
