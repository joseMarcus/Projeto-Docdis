from flask import Flask, request, render_template, url_for, redirect
from flask_restful import Api, Resource
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate



app = Flask(__name__)
api = Api(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:123@localhost/usersdb'  # Substitua com a sua configuração de conexão
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'super-secret'  # Chave secreta para geração do token
jwt = JWTManager(app)
db = SQLAlchemy(app)
migrate = Migrate(app, db)


# Configuração do banco de dados


# ...


class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    date_of_birth = db.Column(db.Date, nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)


class UserRegistration(Resource):
    def post(self):
        name = request.form['name']
        date_of_birth = request.form['date_of_birth']
        username = request.form['username']
        password = request.form['password']

        # Criar uma instância do modelo User
        user = User(name=name, date_of_birth=date_of_birth, username=username, password=password)

        # Adicionar o novo usuário ao banco de dados
        db.session.add(user)
        db.session.commit()

        return render_template('login.html', message='Usuário cadastrado com sucesso.')


class UserLogin(Resource):
    def post(self):
        username = request.form['username']
        password = request.form['password']

        # Verificar credenciais do usuário no banco de dados
        user = User.query.filter_by(username=username, password=password).first()

        if user:
            # Gerar e retornar o token de autenticação
            access_token = create_access_token(identity=username)
            return render_template('protected.html', access_token=access_token)
        else:
            return redirect(url_for('login', error='Credenciais inválidas.'))


class ProtectedResource(Resource):
    @jwt_required()  # Requer autenticação com token para acessar o recurso
    def get(self):
        current_user = get_jwt_identity()
        return {'message': f'Você está visualizando um recurso protegido. Usuário: {current_user}'}, 200


api.add_resource(UserRegistration, '/register')
api.add_resource(UserLogin, '/login')
api.add_resource(ProtectedResource, '/protected')


# ...Amanhã

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if request.method == 'POST':
        # Implemente qualquer lógica necessária para realizar o logout
        # Por exemplo, você pode invalidar o token de acesso
        return render_template('login.html', message='Logout realizado com sucesso.')
    else:
        return render_template('logout.html')



@app.route('/')
def home():
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Processar o formulário de cadastro
        name = request.form['name']
        date_of_birth = request.form['date_of_birth']
        username = request.form['username']
        password = request.form['password']

        # Inserir novo usuário no banco de dados
        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (name, date_of_birth, username, password) VALUES (%s, %s, %s, %s)",
            (name, date_of_birth, username, password)
        )
        db.commit()
        cursor.close()

        return render_template('login.html', message='Usuário cadastrado com sucesso.')
    else:
        return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Processar o formulário de login
        username = request.form['username']
        password = request.form['password']

        # Verificar credenciais do usuário no banco de dados
        cursor = db.cursor()
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        user = cursor.fetchone()
        cursor.close()

        if user:
            # Gerar e retornar o token de autenticação
            access_token = create_access_token(identity=username)
            return render_template('protected.html', access_token=access_token)
        else:
            return render_template('login.html', error='Credenciais inválidas.')
    else:
        return render_template('login.html')


@app.route('/protected')
@jwt_required()  # Requer autenticação com token para acessar o recurso
def protected():
    current_user = get_jwt_identity()
    return render_template('protected.html', current_user=current_user)


# ...


if __name__ == '__main__':
    app.run(debug=True)
