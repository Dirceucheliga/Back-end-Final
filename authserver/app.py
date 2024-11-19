from fastapi import FastAPI, HTTPException, status, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from sqlalchemy import Column, String, Integer, Table, ForeignKey, create_engine
from sqlalchemy.orm import sessionmaker, relationship, Session, declarative_base
from sqlalchemy.exc import IntegrityError
from datetime import datetime, timedelta
from jose import JWTError, jwt

# Configuração do banco de dados
DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Configuração do FastAPI
app = FastAPI(title="AuthServer API")

# Configuração do segredo JWT
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Modelos de dados com SQLAlchemy
user_roles = Table(
    "user_roles", Base.metadata,
    Column("user_id", ForeignKey("users.id")),
    Column("role_id", ForeignKey("roles.id"))
)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, nullable=False)
    email = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    roles = relationship("Role", secondary=user_roles)

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String, unique=True, nullable=False)
    description = Column(String)

Base.metadata.create_all(bind=engine)

# Schemas Pydantic
class RoleBase(BaseModel):
    name: str
    description: str

class RoleResponse(RoleBase):
    id: int

class UserBase(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserCreate(UserBase):
    roles: List[int] = []

class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    roles: List[RoleResponse]  # Inclui os roles associados

class Token(BaseModel):
    access_token: str
    token_type: str

class RoleUpdate(BaseModel):
    roles: List[int]

# Dependências
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Middleware de autenticação JWT
class JWTBearer(HTTPBearer):
    def __init__(self, auto_error: bool = True):
        super(JWTBearer, self).__init__(auto_error=auto_error)

    async def __call__(self, request: Request):
        credentials = await super(JWTBearer, self).__call__(request)
        if credentials:
            if not credentials.scheme == "Bearer":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authentication scheme."
                )
            if not self.verify_jwt(credentials.credentials):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN, detail="Invalid or expired token."
                )
            return credentials.credentials
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Invalid authorization code."
            )

    def verify_jwt(self, jwt_token: str) -> bool:
        try:
            # Verifica se o JWT é válido
            payload = jwt.decode(jwt_token, SECRET_KEY, algorithms=[ALGORITHM])
        except JWTError:
            return False
        return True

auth_scheme = JWTBearer()

# Serviço para criar usuários
class UserService:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, user: UserCreate) -> User:
        db_user = User(name=user.name, email=user.email, password=user.password)
        if user.roles:
            roles = self.db.query(Role).filter(Role.id.in_(user.roles)).all()
            db_user.roles.extend(roles)
        try:
            self.db.add(db_user)
            self.db.commit()
            self.db.refresh(db_user)
            return db_user
        except IntegrityError:
            self.db.rollback()
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email já existe")

    def get_user(self, user_id: int) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        return self.db.query(User).filter(User.email == email).first()

    def delete_user(self, user_id: int):
        user = self.get_user(user_id)
        if user:
            self.db.delete(user)
            self.db.commit()
            return True
        return False

    def update_user_roles(self, user_id: int, roles: List[int]):
        user = self.get_user(user_id)
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
        role_objects = self.db.query(Role).filter(Role.id.in_(roles)).all()
        user.roles = role_objects
        self.db.commit()
        return user

# Função para criar o token JWT
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Função para obter o usuário atual
def get_current_user(db: Session = Depends(get_db), token: str = Depends(auth_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token inválido")
    user = db.query(User).filter(User.email == email).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Usuário não encontrado")
    return user

# Endpoints de autenticação e usuários
@app.post("/users", status_code=status.HTTP_201_CREATED)
def create_user(user: UserCreate, db: Session = Depends(get_db)):
    service = UserService(db)
    db_user = service.create_user(user)
    access_token = create_access_token(data={"sub": db_user.email})

    # Retorno com o token e uma mensagem clara
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "message": "Usuário criado com sucesso! Use o token abaixo para autenticação.",
            "token": access_token,
            "instructions": "Copie o token acima e insira no cabeçalho Authorization: Bearer <seu_token>."
        }
    )

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    service = UserService(db)
    user = service.get_user_by_email(form_data.username)
    if not user or user.password != form_data.password:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciais inválidas")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users", response_model=List[UserResponse])
def get_all_users(db: Session = Depends(get_db)):
    return db.query(User).all()

@app.get("/users/me", response_model=UserResponse)
def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/users/{user_id}", response_model=UserResponse)
def get_user(user_id: int, db: Session = Depends(get_db)):
    service = UserService(db)
    user = service.get_user(user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado")
    return user

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    token: str = Depends(auth_scheme),
):
    service = UserService(db)
    if not service.delete_user(user_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuário não encontrado"
        )

@app.patch("/users/{user_id}/roles", response_model=UserResponse)
def update_user_roles(
    user_id: int, role_update: RoleUpdate, db: Session = Depends(get_db)
):
    service = UserService(db)
    updated_user = service.update_user_roles(user_id, role_update.roles)
    return updated_user

@app.post("/roles", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
def create_role(role: RoleBase, db: Session = Depends(get_db)):
    db_role = Role(name=role.name, description=role.description)
    try:
        db.add(db_role)
        db.commit()
        db.refresh(db_role)
        return db_role
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Função já existe")

@app.get("/roles", response_model=List[RoleResponse])
def get_roles(db: Session = Depends(get_db)):
    return db.query(Role).all()

# Configuração inicial do Swagger
@app.get("/")
async def root():
    return {"message": "Bem-vindo à API com Autenticação JWT"}
