from pydantic import BaseModel, EmailStr
from typing import Optional

# Esquema para crear un nuevo usuario
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

# Esquema para la respuesta de un usuario (sin contraseña)
class UserInDB(BaseModel):
    username: str
    email: EmailStr
    hashed_password: str
    # Puedes añadir más campos como id, is_active, roles, etc.

# Esquema para el login del usuario
class UserLogin(BaseModel):
    username: str
    password: str

# Esquema para los datos que se guardan en el JWT
class TokenData(BaseModel):
    username: Optional[str] = None

# Esquema para la respuesta del token (access_token y tipo de token)
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"