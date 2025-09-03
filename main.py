
import os
import csv
import io
import datetime as dt
from typing import Optional, List, Annotated

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from passlib.context import CryptContext
import jwt

from sqlalchemy import (
    create_engine, String, Integer, Float, Date, ForeignKey, Text, select, func
)
from sqlalchemy.orm import declarative_base, Mapped, mapped_column, relationship, Session

# -----------------------
# Config / Env
# -----------------------
SECRET_KEY = os.getenv("SECRET_KEY", "dev_secret_change_me")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "120"))
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./expensetracker.db")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=False,
)
Base = declarative_base()

# -----------------------
# DB Models
# -----------------------
class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(default=dt.datetime.utcnow)

    categories: Mapped[List["Category"]] = relationship(back_populates="owner", cascade="all, delete-orphan")
    transactions: Mapped[List["Transaction"]] = relationship(back_populates="owner", cascade="all, delete-orphan")


class Category(Base):
    __tablename__ = "categories"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(100))
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    owner: Mapped[User] = relationship(back_populates="categories")
    transactions: Mapped[List["Transaction"]] = relationship(back_populates="category")


class Transaction(Base):
    __tablename__ = "transactions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    date: Mapped[dt.date] = mapped_column(Date, index=True)
    description: Mapped[str] = mapped_column(Text)
    amount: Mapped[float] = mapped_column(Float)  # positive numbers; use type field for income/expense
    type: Mapped[str] = mapped_column(String(10))  # "expense" | "income"
    category_id: Mapped[Optional[int]] = mapped_column(ForeignKey("categories.id", ondelete="SET NULL"), nullable=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"))

    category: Mapped[Optional[Category]] = relationship(back_populates="transactions")
    owner: Mapped[User] = relationship(back_populates="transactions")


Base.metadata.create_all(engine)

# -------------------
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True


class CategoryIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class CategoryOut(BaseModel):
    id: int
    name: str
    class Config:
        from_attributes = True


class TxIn(BaseModel):
    date: dt.date
    description: str
    amount: float = Field(gt=0)
    type: str = Field(pattern="^(expense|income)$")
    category_id: Optional[int] = None


class TxOut(BaseModel):
    id: int
    date: dt.date
    description: str
    amount: float
    type: str
    category_id: Optional[int]
    category_name: Optional[str] = None
    class Config:
        from_attributes = True


class ReportItem(BaseModel):
    category_name: Optional[str]
    total_expense: float
    total_income: float


# -----------------------
# Auth utils
# -----------------------
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_db():
    with Session(engine) as session:
        yield session

def get_user_from_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        uid: int = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

UserDep = Annotated[User, Depends(get_user_from_token)]

# -----------------------
# App
# -----------------------
app = FastAPI(title="Expense Tracker API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Auth routes
# -----------------------
@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    exists = db.scalar(select(User).where(User.email == user.email))
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    u = User(email=user.email, password_hash=hash_password(user.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    # Create 3 default categories to get started
    for name in ["General", "Food", "Transport"]:
        db.add(Category(name=name, owner_id=u.id))
    db.commit()
    return u

@app.post("/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == form.username))
    if not u or not verify_password(form.password, u.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": str(u.id)})
    return Token(access_token=token)

# -----------------------
# Category routes
# -----------------------
@app.get("/categories", response_model=List[CategoryOut])
def list_categories(current_user: UserDep, db: Session = Depends(get_db)):
    cats = db.scalars(select(Category).where(Category.owner_id == current_user.id).order_by(Category.name)).all()
    return cats

@app.post("/categories", response_model=CategoryOut, status_code=201)
def create_category(payload: CategoryIn, current_user: UserDep, db: Session = Depends(get_db)):
    c = Category(name=payload.name, owner_id=current_user.id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c

@app.put("/categories/{category_id}", response_model=CategoryOut)
def update_category(category_id: int, payload: CategoryIn, current_user: UserDep, db: Session = Depends(get_db)):
    c = db.get(Category, category_id)
    if not c or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Category not found")
    c.name = payload.name
    db.commit()
    db.refresh(c)
    return c

@app.delete("/categories/{category_id}", status_code=204)
def delete_category(category_id: int, current_user: UserDep, db: Session = Depends(get_db)):
    c = db.get(Category, category_id)
    if not c or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Category not found")
    db.delete(c)
    db.commit()
    return Response(status_code=204)

# -----------------------
# Transaction routes
# -----------------------
@app.get("/transactions", response_model=List[TxOut])
def list_transactions(
    current_user: UserDep,
    db: Session = Depends(get_db),
    q: Optional[str] = None,
    type: Optional[str] = None,
    category_id: Optional[int] = None,
    start: Optional[dt.date] = None,
    end: Optional[dt.date] = None,
    limit: int = 50,
    offset: int = 0,
):
    stmt = select(Transaction).where(Transaction.owner_id == current_user.id)
    if q:
        stmt = stmt.where(Transaction.description.ilike(f"%{q}%"))
    if type in ("expense", "income"):
        stmt = stmt.where(Transaction.type == type)
    if category_id:
        stmt = stmt.where(Transaction.category_id == category_id)
    if start:
        stmt = stmt.where(Transaction.date >= start)
    if end:
        stmt = stmt.where(Transaction.date <= end)
    stmt = stmt.order_by(Transaction.date.desc()).limit(limit).offset(offset)
    txs = db.scalars(stmt).all()
    out = []
    for t in txs:
        out.append(TxOut(
            id=t.id, date=t.date, description=t.description, amount=t.amount,
            type=t.type, category_id=t.category_id,
            category_name=(t.category.name if t.category else None)
        ))
    return out

@app.post("/transactions", response_model=TxOut, status_code=201)
def create_transaction(payload: TxIn, current_user: UserDep, db: Session = Depends(get_db)):
    if payload.category_id:
        cat = db.get(Category, payload.category_id)
        if not cat or cat.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Category not found")
    tx = Transaction(
        date=payload.date,
        description=payload.description,
        amount=payload.amount,
        type=payload.type,
        category_id=payload.category_id,
        owner_id=current_user.id,
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)
    return TxOut(
        id=tx.id, date=tx.date, description=tx.description, amount=tx.amount,
        type=tx.type, category_id=tx.category_id,
        category_name=(tx.category.name if tx.category else None)
    )

@app.put("/transactions/{tx_id}", response_model=TxOut)
def update_transaction(tx_id: int, payload: TxIn, current_user: UserDep, db: Session = Depends(get_db)):
    tx = db.get(Transaction, tx_id)
    if not tx or tx.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if payload.category_id:
        cat = db.get(Category, payload.category_id)
        if not cat or cat.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Category not found")
    tx.date = payload.date
    tx.description = payload.description
    tx.amount = payload.amount
    tx.type = payload.type
    tx.category_id = payload.category_id
    db.commit()
    db.refresh(tx)
    return TxOut(
        id=tx.id, date=tx.date, description=tx.description, amount=tx.amount,
        type=tx.type, category_id=tx.category_id,
        category_name=(tx.category.name if tx.category else None)
    )
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class UserCreate(BaseModel):
    email: str
    password: str


class UserOut(BaseModel):
    id: int
    email: str
    class Config:
        from_attributes = True


class CategoryIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)


class CategoryOut(BaseModel):
    id: int
    name: str
    class Config:
        from_attributes = True


class TxIn(BaseModel):
    date: dt.date
    description: str
    amount: float = Field(gt=0)
    type: str = Field(pattern="^(expense|income)$")
    category_id: Optional[int] = None


class TxOut(BaseModel):
    id: int
    date: dt.date
    description: str
    amount: float
    type: str
    category_id: Optional[int]
    category_name: Optional[str] = None
    class Config:
        from_attributes = True


class ReportItem(BaseModel):
    category_name: Optional[str]
    total_expense: float
    total_income: float


# -----------------------
# Auth utils
# -----------------------
def hash_password(pw: str) -> str:
    return pwd_context.hash(pw)

def verify_password(pw: str, pw_hash: str) -> bool:
    return pwd_context.verify(pw, pw_hash)

def create_access_token(data: dict, expires_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES) -> str:
    to_encode = data.copy()
    expire = dt.datetime.utcnow() + dt.timedelta(minutes=expires_minutes)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm="HS256")

def get_db():
    with Session(engine) as session:
        yield session

def get_user_from_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        uid: int = int(payload.get("sub"))
    except Exception:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.get(User, uid)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user

UserDep = Annotated[User, Depends(get_user_from_token)]

# -----------------------
# App
# -----------------------
app = FastAPI(title="Expense Tracker API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------
# Auth routes
# -----------------------
@app.post("/auth/register", response_model=UserOut, status_code=201)
def register(user: UserCreate, db: Session = Depends(get_db)):
    exists = db.scalar(select(User).where(User.email == user.email))
    if exists:
        raise HTTPException(status_code=400, detail="Email already registered")
    u = User(email=user.email, password_hash=hash_password(user.password))
    db.add(u)
    db.commit()
    db.refresh(u)
    # Create 3 default categories to get started
    for name in ["General", "Food", "Transport"]:
        db.add(Category(name=name, owner_id=u.id))
    db.commit()
    return u

@app.post("/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    u = db.scalar(select(User).where(User.email == form.username))
    if not u or not verify_password(form.password, u.password_hash):
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    token = create_access_token({"sub": str(u.id)})
    return Token(access_token=token)

# -----------------------
# Category routes
# -----------------------
@app.get("/categories", response_model=List[CategoryOut])
def list_categories(current_user: UserDep, db: Session = Depends(get_db)):
    cats = db.scalars(select(Category).where(Category.owner_id == current_user.id).order_by(Category.name)).all()
    return cats

@app.post("/categories", response_model=CategoryOut, status_code=201)
def create_category(payload: CategoryIn, current_user: UserDep, db: Session = Depends(get_db)):
    c = Category(name=payload.name, owner_id=current_user.id)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c

@app.put("/categories/{category_id}", response_model=CategoryOut)
def update_category(category_id: int, payload: CategoryIn, current_user: UserDep, db: Session = Depends(get_db)):
    c = db.get(Category, category_id)
    if not c or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Category not found")
    c.name = payload.name
    db.commit()
    db.refresh(c)
    return c

@app.delete("/categories/{category_id}", status_code=204)
def delete_category(category_id: int, current_user: UserDep, db: Session = Depends(get_db)):
    c = db.get(Category, category_id)
    if not c or c.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Category not found")
    db.delete(c)
    db.commit()
    return Response(status_code=204)

# -----------------------
# Transaction routes
# -----------------------
@app.get("/transactions", response_model=List[TxOut])
def list_transactions(
    current_user: UserDep,
    db: Session = Depends(get_db),
    q: Optional[str] = None,
    type: Optional[str] = None,
    category_id: Optional[int] = None,
    start: Optional[dt.date] = None,
    end: Optional[dt.date] = None,
    limit: int = 50,
    offset: int = 0,
):
    stmt = select(Transaction).where(Transaction.owner_id == current_user.id)
    if q:
        stmt = stmt.where(Transaction.description.ilike(f"%{q}%"))
    if type in ("expense", "income"):
        stmt = stmt.where(Transaction.type == type)
    if category_id:
        stmt = stmt.where(Transaction.category_id == category_id)
    if start:
        stmt = stmt.where(Transaction.date >= start)
    if end:
        stmt = stmt.where(Transaction.date <= end)
    stmt = stmt.order_by(Transaction.date.desc()).limit(limit).offset(offset)
    txs = db.scalars(stmt).all()
    out = []
    for t in txs:
        out.append(TxOut(
            id=t.id, date=t.date, description=t.description, amount=t.amount,
            type=t.type, category_id=t.category_id,
            category_name=(t.category.name if t.category else None)
        ))
    return out

@app.post("/transactions", response_model=TxOut, status_code=201)
def create_transaction(payload: TxIn, current_user: UserDep, db: Session = Depends(get_db)):
    if payload.category_id:
        cat = db.get(Category, payload.category_id)
        if not cat or cat.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Category not found")
    tx = Transaction(
        date=payload.date,
        description=payload.description,
        amount=payload.amount,
        type=payload.type,
        category_id=payload.category_id,
        owner_id=current_user.id,
    )
    db.add(tx)
    db.commit()
    db.refresh(tx)
    return TxOut(
        id=tx.id, date=tx.date, description=tx.description, amount=tx.amount,
        type=tx.type, category_id=tx.category_id,
        category_name=(tx.category.name if tx.category else None)
    )

@app.put("/transactions/{tx_id}", response_model=TxOut)
def update_transaction(tx_id: int, payload: TxIn, current_user: UserDep, db: Session = Depends(get_db)):
    tx = db.get(Transaction, tx_id)
    if not tx or tx.owner_id != current_user.id:
        raise HTTPException(status_code=404, detail="Transaction not found")
    if payload.category_id:
        cat = db.get(Category, payload.category_id)
        if not cat or cat.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Category not found")
    tx.date = payload.date
    tx.description = payload.description
    tx.amount = payload.amount
    tx.type = payload.type
    tx.category_id = payload.category_id
    db.commit()
    db.refresh(tx)
    return TxOut(
        id=tx.id, date=tx.date, description=tx.description, amount=tx.amount,
        type=tx.type, category_id=tx.category_id,
        category_name=(tx.category.name if tx.category else None)
    )