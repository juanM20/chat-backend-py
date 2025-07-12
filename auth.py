from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import settings # Asume que tu config.py está en el mismo nivel
from .schemas import TokenData, UserLogin, UserInDB # Importa tus esquemas

# Configuración de hashing de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Configuración de OAuth2 con esquema de token bearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token") # tokenUrl es el endpoint de login

# --- Funciones de Hashing de Contraseñas ---
def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si una contraseña en texto plano coincide con una hasheada."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hashea una contraseña."""
    return pwd_context.hash(password)

# --- Funciones de JWT ---
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Crea un nuevo JWT de acceso."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> UserInDB:
    """
    Decodifica el token JWT y obtiene el usuario actual.
    Lanza una excepción si el token es inválido o el usuario no existe.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudieron validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub") # 'sub' es la convención para el sujeto (username)
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception

    # Aquí simularíamos la búsqueda del usuario en la base de datos
    # Por ahora, un usuario "dummy"
    # En un proyecto real, esto sería una consulta a tu DB
    if token_data.username == "testuser": # Asumiendo un usuario de prueba para el ejemplo
        user_db = UserInDB(
            username="testuser",
            email="test@example.com",
            hashed_password=get_password_hash("testpassword") # Hashed password of "testpassword"
        )
        return user_db
    else:
        raise credentials_exception

# Función para verificar las credenciales de login (simulado)
# En un proyecto real, buscarías el usuario en la DB y verificarías la contraseña.
async def authenticate_user(username: str, password: str) -> Optional[UserInDB]:
    """Simula la autenticación de un usuario."""
    # Buscar usuario en la base de datos (aquí simulado)
    if username == "testuser":
        user_in_db = UserInDB(
            username="testuser",
            email="test@example.com",
            hashed_password=get_password_hash("testpassword") # Esto debería ser la contraseña hasheada del usuario en tu DB
        )
        if verify_password(password, user_in_db.hashed_password):
            return user_in_db
    return None