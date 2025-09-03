# Expense Tracker API

A secure and scalable **backend API for personal finance management**, built with **FastAPI** and **SQLAlchemy**. This project allows users to register accounts, categorize expenses and income, log transactions, generate financial reports, and import/export data via CSV.  

Designed to demonstrate **real-world backend engineering skills**: authentication, relational data modeling, reporting, and clean API design — all production-ready for front-end or mobile integration.  

---

## Features

- **User Authentication & Security**  
  - Register and log in with hashed passwords (bcrypt)  
  - JWT-based authentication for protected endpoints  

- **Categories**  
  - Create, update, delete, and view categories (e.g., Food, Rent, Salary)  
  - Assign budgets to categories (optional)  

- **Transactions**  
  - Log expenses or income with date, description, amount, and category  
  - Full CRUD support with filtering by date, category, or type  

- **Reports**  
  - Monthly financial summaries (income vs. expenses by category)  
  - Daily breakdowns (optional feature)  

- 📂 **CSV Support**  
  - Bulk import transactions from CSV files  
  - Export all transactions for external analysis  

- ⚡ **Extensible Architecture**  
  - Easy to integrate with front-end frameworks (React, Vue, Angular)  
  - Ready for deployment to cloud environments  

---

## Tech Stack

- **Framework:** FastAPI (Python)  
- **Database:** SQLite (default) – swappable with PostgreSQL/MySQL  
- **ORM:** SQLAlchemy 2.0  
- **Authentication:** OAuth2 with JWT  
- **Security:** Passlib (bcrypt password hashing)  
- **Server:** Uvicorn  

---

## Installation

```bash
# 1. Clone the repo
git clone https://github.com/yourusername/expense-tracker.git
cd expense-tracker

# 2. Create a virtual environment
python3 -m venv .venv

# 3. Activate the environment
source .venv/bin/activate   # macOS / Linux
# On Windows:
# .venv\Scripts\activate

# 4. Install dependencies
pip install --upgrade pip
pip install fastapi "uvicorn[standard]" sqlalchemy pydantic "passlib[bcrypt]" PyJWT python-multipart

# 5. Save dependencies
pip freeze > requirements.txt

# 6. Run the server
uvicorn main:app --reload
