from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField
from wtforms.validators import DataRequired


print(generate_password_hash("password1", method="pbkdf2:sha256"))
print(generate_password_hash("mypassword", method="pbkdf2:sha256"))
print(generate_password_hash("lindasflores", method="pbkdf2:sha256"))
print(generate_password_hash("cocanegra", method="pbkdf2:sha256"))
print(generate_password_hash("soprole", method="pbkdf2:sha256"))
print(generate_password_hash("fanta", method="pbkdf2:sha256"))

app = Flask(__name__)
csrf = CSRFProtect(app)
app.secret_key = 'clave_secreta_segura'  # Clave para sesiones


# Definir el formulario con Flask-WTF
class LoginForm(FlaskForm):
    username = StringField('Usuario', validators=[DataRequired()])
    password = PasswordField('Contraseña', validators=[DataRequired()])


# Diccionario para rastrear intentos fallidos por usuario
login_attempts = {}
LOCKOUT_TIME = timedelta(minutes=5)  # Bloqueo de 5 minutos después de superar los intentos permitidos
MAX_ATTEMPTS = 3  # Número máximo de intentos permitidos


# Ruta para la página principal
@app.route('/')
def home():
    return render_template('login.html')

# Ruta para el registro
@app.route('/registro', methods=['GET', 'POST'])
def registro():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Validar y guardar en la base de datos
        hash_password = generate_password_hash(password)
        con = sqlite3.connect('database/usuarios.db')
        cur = con.cursor()
        cur.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (username, hash_password))
        con.commit()
        con.close()
        return redirect(url_for('home'))
    return render_template('registro.html')

# Diccionario para rastrear intentos fallidos por usuario
attempts = {}

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm() #Crear una instancia del formulario
    if form.validate_on_submit(): #Validar los datos cuando se envie el formulario
        username = form.username.data
        password = form.password.data
        #Aquí tu lógica para verificar las credenciales
        return 'Inicio de sesión exitoso' #Redirige a donde quieras
    return render_template('login.html', form=form) #Pasa el formulario a la plantilla
    global attempts  # Para modificar el diccionario global
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Inicializa los intentos para el usuario si no existe
        if username not in attempts:
            attempts[username] = 0

        # Verificar en la base de datos
        con = sqlite3.connect('database/usuarios.db')
        cur = con.cursor()
        cur.execute("SELECT password FROM usuarios WHERE username = ?", (username,))
        user = cur.fetchone()
        con.close()

        if user and check_password_hash(user[0], password):
            session['username'] = username
            attempts[username] = 0  # Reiniciar intentos en caso de éxito
            return redirect(url_for('dashboard'))

        # Incrementar intentos fallidos
        attempts[username] += 1
        remaining_attempts = 3 - attempts[username]

        # Mostrar mensajes de error según los intentos restantes
        if remaining_attempts > 0:
            flash(f"Usuario o contraseña incorrectos. Te quedan {remaining_attempts} intentos.")
        else: 
            flash("Demasiados intentos fallidos. Intenta nuevamente más tarde.")


    return render_template('login.html', form=form)
import os


@app.route('/dashboard')
def dashboard():
    if 'username' in session:
        # Ruta de la carpeta donde están las imágenes
        image_folder = os.path.join(app.static_folder, 'images')
        
        # Buscar la imagen del usuario con cualquier extensión
        extensions = ['jpg', 'jpeg', 'png']
        profile_image = None
        for ext in extensions:
            potential_path = os.path.join(image_folder, f"{session['username']}.{ext}")
            if os.path.exists(potential_path):
                profile_image = f"{session['username']}.{ext}"
                break
        
        # Renderizar el template y pasar la imagen al dashboard
        return render_template('dashboard.html', username=session['username'], profile_image=profile_image)
    
    # Redirigir al login si no hay sesión activa
    return redirect(url_for('home'))


@app.route('/logout')
def logout():
    session.pop('username', None)  # Elimina el nombre de usuario de la sesión
    return redirect(url_for('home'))  # Redirige a la página de inicio


# Inicializar la base de datos
def init_db():
    con = sqlite3.connect('database/usuarios.db')
    cur = con.cursor()
    cur.execute('''CREATE TABLE IF NOT EXISTS usuarios (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    profile_image TEXT)''')
    con.close()

if __name__ == '__main__':
    init_db()  #Inicializa la base de datos y crea la tabla si no existe
    app.run(debug=True)
