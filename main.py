from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import load_dotenv
import os
import bcrypt
import jwt
from datetime import datetime, timedelta

load_dotenv()

app = FastAPI(title="МоскваДрайв API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "supersecretkey123"
ALGORITHM = "HS256"

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

def get_db_connection():
    return psycopg2.connect(
        host=os.getenv("DB_HOST", "localhost"),
        database="mosdriv",
        user=os.getenv("DB_USER", "postgres"),
        password=os.getenv("DB_PASSWORD", "1234"),
        cursor_factory=RealDictCursor
    )

class UserRegister(BaseModel):
    full_name: str
    phone: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class BookingRequest(BaseModel):
    car_id: int
    tariff_type: str = "minute"

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=60)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except:
        raise HTTPException(status_code=401, detail="Invalid token")

def is_admin(token: str = Depends(oauth2_scheme)):
    email = get_current_user(token)
    if email.lower() != "admin@mosdriv.ru":
        raise HTTPException(status_code=403, detail="Доступ только для администратора")
    return email

# ====================== РЕГИСТРАЦИЯ И ЛОГИН ======================
@app.post("/register")
async def register(user: UserRegister):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s OR phone = %s", (user.email, user.phone))
            if cur.fetchone():
                raise HTTPException(status_code=400, detail="Пользователь уже существует")
            
            role = 'admin' if user.email.lower() == 'admin@mosdriv.ru' else 'user'
            hashed = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
            
            cur.execute("""
                INSERT INTO users (full_name, phone, email, password_hash, role)
                VALUES (%s, %s, %s, %s, %s)
            """, (user.full_name, user.phone, user.email, hashed.decode('utf-8'), role))
            conn.commit()
        return {"success": True, "message": "Регистрация прошла успешно"}
    finally:
        conn.close()

@app.post("/login", response_model=Token)
async def login(user: UserLogin):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE email = %s", (user.email,))
            record = cur.fetchone()
            if not record or not bcrypt.checkpw(user.password.encode('utf-8'), record['password_hash'].encode('utf-8')):
                raise HTTPException(status_code=401, detail="Неверный email или пароль")
            token = create_access_token({"sub": user.email})
            return {"access_token": token, "token_type": "bearer"}
    finally:
        conn.close()

# ====================== ОСНОВНЫЕ ======================
@app.get("/api/cars")
async def get_all_cars():
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, model, color, year, license_plate, 
                       tariff_per_minute, tariff_per_day, status, latitude, longitude 
                FROM cars WHERE status = 'available'
            """)
            return cur.fetchall()
    finally:
        conn.close()

@app.post("/api/book")
async def book_car(request: BookingRequest, token: str = Depends(oauth2_scheme)):
    email = get_current_user(token)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM users WHERE email = %s", (email,))
            user = cur.fetchone()

            cur.execute("SELECT tariff_per_minute, tariff_per_day, status FROM cars WHERE id = %s", (request.car_id,))
            car = cur.fetchone()
            if not car or car['status'] != 'available':
                raise HTTPException(status_code=400, detail="Автомобиль недоступен")

            total_cost = car['tariff_per_day'] if request.tariff_type == "day" else car['tariff_per_minute']

            cur.execute("UPDATE cars SET status = 'booked' WHERE id = %s", (request.car_id,))
            cur.execute("""
                INSERT INTO bookings (user_id, car_id, start_time, status, total_cost)
                VALUES (%s, %s, NOW(), 'active', %s)
            """, (user['id'], request.car_id, total_cost))
            conn.commit()

        return {"success": True, "message": "Автомобиль успешно забронирован", "total_cost": float(total_cost)}
    finally:
        conn.close()

@app.get("/api/my-bookings")
async def get_my_bookings(token: str = Depends(oauth2_scheme)):
    email = get_current_user(token)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT b.id as booking_id, c.model, c.license_plate, 
                       b.start_time, b.total_cost, b.status
                FROM bookings b
                JOIN cars c ON b.car_id = c.id
                JOIN users u ON b.user_id = u.id
                WHERE u.email = %s
                ORDER BY b.start_time DESC
            """, (email,))
            return cur.fetchall()
    finally:
        conn.close()

# ====================== ОТМЕНА И ОПЛАТА ======================
@app.post("/api/cancel-booking")
async def cancel_booking(booking_id: int, token: str = Depends(oauth2_scheme)):
    email = get_current_user(token)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT b.car_id FROM bookings b
                JOIN users u ON b.user_id = u.id
                WHERE b.id = %s AND u.email = %s AND b.status = 'active'
            """, (booking_id, email))
            booking = cur.fetchone()
            if not booking:
                raise HTTPException(status_code=404, detail="Бронь не найдена или уже обработана")

            cur.execute("UPDATE bookings SET status = 'cancelled' WHERE id = %s", (booking_id,))
            cur.execute("UPDATE cars SET status = 'available' WHERE id = %s", (booking['car_id'],))
            conn.commit()
            
        return {"success": True, "message": "Бронь успешно отменена"}
    finally:
        conn.close()

@app.post("/api/pay-booking")
async def pay_booking(booking_id: int, token: str = Depends(oauth2_scheme)):
    email = get_current_user(token)
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT b.car_id FROM bookings b
                JOIN users u ON b.user_id = u.id
                WHERE b.id = %s AND u.email = %s AND b.status = 'active'
            """, (booking_id, email))
            booking = cur.fetchone()
            if not booking:
                raise HTTPException(status_code=404, detail="Бронь не найдена или уже обработана")

            cur.execute("UPDATE bookings SET status = 'paid' WHERE id = %s", (booking_id,))
            conn.commit()
            
        return {"success": True, "message": "Оплата прошла успешно! Спасибо!"}
    finally:
        conn.close()

# ====================== АДМИН ======================
@app.get("/api/admin/users")
async def get_all_users(token: str = Depends(is_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id, full_name, email, phone, role, created_at FROM users ORDER BY created_at DESC")
            return cur.fetchall()
    finally:
        conn.close()

@app.get("/api/admin/bookings")
async def get_all_bookings(token: str = Depends(is_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT b.id, u.full_name, u.email, c.model, c.license_plate, 
                       b.start_time, b.total_cost, b.status
                FROM bookings b
                JOIN users u ON b.user_id = u.id
                JOIN cars c ON b.car_id = c.id
                ORDER BY b.start_time DESC
            """)
            return cur.fetchall()
    finally:
        conn.close()

@app.delete("/api/admin/delete-user/{user_id}")
async def admin_delete_user(user_id: int, token: str = Depends(is_admin)):
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            conn.commit()
        return {"success": True, "message": "Пользователь успешно удалён"}
    finally:
        conn.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)