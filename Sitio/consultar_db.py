import sqlite3
from werkzeug.security import generate_password_hash

# Conectar a la base de datos
con = sqlite3.connect('database/usuarios.db')
cursor = con.cursor()

# Asegúrate de que la tabla 'usuarios' esté creada
cursor.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL)''')

# Insertar algunos usuarios
usuarios = [
    ('admin', generate_password_hash('admin123')),
    ('usuario1', generate_password_hash('password1')),
    ('usuario2', generate_password_hash('password2'))
]

cursor.executemany("INSERT OR IGNORE INTO usuarios (username, password) VALUES (?, ?)", usuarios)

# Confirmar cambios y cerrar la conexión
con.commit()
con.close()

print("Usuarios insertados correctamente.")

