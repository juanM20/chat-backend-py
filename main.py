# main.py (o puedes usar APIRouter para modularizar)

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm # Para el formulario de login

from . import schemas, auth # Importa tus esquemas y lógica de auth

app = FastAPI()

# --- Ruta de Login (para obtener el token de acceso) ---
@app.post("/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await auth.authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciales incorrectas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=auth.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = auth.create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# --- Ruta Protegida (Requiere Autenticación) ---
@app.get("/users/me/", response_model=schemas.UserCreate) # Usamos UserCreate para la respuesta simplificada
async def read_users_me(current_user: schemas.UserInDB = Depends(auth.get_current_user)):
    """Obtiene información del usuario autenticado."""
    # current_user ya contiene los datos del usuario autenticado desde el token
    # Puedes devolver los datos que quieras, aquí un ejemplo simplificado
    return schemas.UserCreate(username=current_user.username, email=current_user.email, password="[HIDDEN]")

# --- Otra ruta protegida de ejemplo ---
@app.get("/items_protegidos/")
async def read_items_protegidos(current_user: schemas.UserInDB = Depends(auth.get_current_user)):
    return {"message": f"Estos son ítems protegidos, {current_user.username} tiene acceso."}

# Ruta pública de ejemplo
@app.get("/")
async def read_root():
    return {"message": "¡Hola, esta es una ruta pública!"}