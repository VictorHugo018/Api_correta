from flask import Flask, jsonify, request
from main import app, con
import re
from flask_bcrypt import generate_password_hash, check_password_hash

import jwt

senha_secreta = app.config['SECRET_KEY']

def generate_token(user_id):
    payload = {'id_usuario': user_id}
    token = jwt.encode(payload, senha_secreta, algorithm='HS256')
    return token

def remover_bearer(token):
    if token.startswith('Bearer '):
        return token[len('Bearer '):]
    else:
        return token

@app.route('/Livros', methods=['GET'])
def livros():
    cur = con.cursor()
    cur.execute('SELECT id_livro, titulo, autor, ano_publicacao FROM livros')
    livros = cur.fetchall()
    livros_dic = []
    for livro in livros:
        livros_dic.append({
            'id_livro': livro[0],
            'titulo': livro[1],
            'autor': livro[2],
            'ano_publicacao': livro[3]
        })
        return jsonify(mensagens='Lista de livros', livros=livros_dic)


@app.route('/Livros', methods=['POST'])
def livros_post():
    token = request.headers.get('Authorization')
    if not token:
        return jsonify({'mensage': 'Token de autenticação necessário'}), 401

    token = remover_bearer(token)
    try:
        payload = jwt.decode(token, senha_secreta, algorithms=['HS256'])
        id_usuario = payload['id_usuario']
    except jwt.ExpiredSignatureError:
        return jsonify({'mensagem': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'mensagem': 'Token inválido'}), 401

    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor = con.cursor()
    cursor.execute("SELECT 1 FROM LIVROS WHERE TITULO = ?", (titulo, ))

    if cursor.fetchone():
        return jsonify({"mensagem": "Livro já cadastrado"})


    cursor.execute("INSERT INTO LIVROS (TITULO, AUTOR, ANO_PUBLICACAO) VALUES (?,?,?)",
                   (titulo, autor, ano_publicacao))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro cadastrado com sucesso!",
        'Livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    }), 201


@app.route('/Livros/<int:id>', methods = ['PUT'])
def livros_get(id):
    cursor = con.cursor()

    cursor.execute('SELECT id_livro, titulo, autor, ano_publicacao FROM LIVROS WHERE id_livro = ?', (id,))
    livro_data = cursor.fetchall()

    if not livro_data:
        cursor.close()
        return jsonify({"Livro não encontrado"})

    data = request.get_json()
    titulo = data.get('titulo')
    autor = data.get('autor')
    ano_publicacao = data.get('ano_publicacao')

    cursor.execute("UPDATE LIVROS SET TITULO = ?, AUTOR = ?, ANO_PUBLICACAO = ? WHERE id_livro = ?",
                   (titulo, autor, ano_publicacao, id))

    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro atualizado com sucesso!",
        'livro': {
            'titulo': titulo,
            'autor': autor,
            'ano_publicacao': ano_publicacao
        }
    })


@app.route('/livros/<int:id>', methods=['DELETE'])
def deletar_livro(id):
    cursor = con.cursor()

    # Verificar se o livro existe
    cursor.execute("SELECT 1 FROM livros WHERE ID_LIVRO = ?", (id,))
    if not cursor.fetchone():
        cursor.close()
        return jsonify({"error": "Livro não encontrado"}), 404

    # Excluir o livro
    cursor.execute("DELETE FROM livros WHERE ID_LIVRO = ?", (id,))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Livro excluído com sucesso!",
        'id_livro': id
    })


@app.route('/cadastro', methods=['GET'])
def usuario():
    cur = con.cursor()
    cur.execute("SELECT id_usuario, nome, email, senha FROM Cadastro")
    cadastros = cur.fetchall()
    cadastros_dic = []

    for cadastro in cadastros:
        cadastros_dic.append({
            'id_usuario': cadastro[0]
            , 'nome': cadastro[1]
            , 'email': cadastro[2]
            , 'senha': cadastro[3]
        })
    return jsonify(mensagens='Lista de usuarios', cadastro=cadastros_dic)


@app.route('/cadastro', methods=['POST'])
def criar_usuario():
    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')

    if not nome or not email or not senha:
        return jsonify({"error": "Todos os campos são obrigatórios"}), 400

    if not re.fullmatch(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", senha):
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma minúscula, um número e um caractere especial"}), 400

    cursor = con.cursor()

    senha = generate_password_hash(senha).decode('utf-8')

    cursor.execute("SELECT 1 FROM cadastro WHERE email = ?", (email,))
    if cursor.fetchone():
        cursor.close()
        return jsonify({"error": "E-mail já cadastrado"}), 400

    cursor.execute("INSERT INTO cadastro (nome, email, senha) VALUES (?, ?, ?)",
                   (nome, email, senha))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuário cadastrado com sucesso!",
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    }), 201


@app.route('/cadastro/<int:id>', methods=['PUT'])
def editar_usuario(id):
    cursor = con.cursor()

    cursor.execute("SELECT nome, email, senha FROM cadastro WHERE id_usuario = ?", (id,))
    usuario_data = cursor.fetchone()

    if not usuario_data:
        cursor.close()
        return jsonify({"error": "Usuário não encontrado"}), 404

    data = request.get_json()
    nome = data.get('nome')
    email = data.get('email')
    senha = data.get('senha')


    if not re.fullmatch(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$", senha):
        cursor.close()
        return jsonify({"error": "A senha deve ter pelo menos 8 caracteres, incluindo uma letra maiúscula, uma minúscula, um número e um caractere especial"}), 400

    cursor.execute("UPDATE cadastro SET nome = ?, email = ?, senha = ? WHERE id_usuario = ?",
                   (nome, email, senha, id))
    con.commit()
    cursor.close()

    return jsonify({
        'message': "Usuário atualizado com sucesso!",
        'usuario': {
            'nome': nome,
            'email': email,
            'senha': senha
        }
    })


@app.route('/cadastro/<int:id>', methods=['DELETE'])
def usuario_delete(id):
    cur = con.cursor()

    cur.execute("SELECT 1 FROM CADASTRO WHERE ID_USUARIO = ?", (id,))
    if not cur.fetchone():
        cur.close()
        return jsonify(mensagem="Usuário não encontrado"), 404

    cur.execute("DELETE FROM cadastro WHERE id_usuario =?", (id,))
    con.commit()
    cur.close()

    return jsonify({
        'message': "Usuário excluído com sucesso!",
        'id_usuario': id
    })


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    senha = data.get('senha')

    if not email or not senha:
        return jsonify({'error': "Todos os campos são obrigatórios"}), 400

    cursor = con.cursor()
    cursor.execute('SELECT senha , id_usuario FROM cadastro WHERE email = ?', (email,))
    usuario = cursor.fetchone()
    cursor.close()

    if not usuario:
        return jsonify({'error': "Usuário ou senha inválidos"}), 404

    senha_armazenada = usuario[0]
    id_usuario = senha[1]

    if check_password_hash(senha_armazenada, senha):
        token = generate_token(id_usuario)
        return jsonify({'message': 'Login efetuado com sucesso!', 'token': token}), 200

    return jsonify({'error': "Senha incorreta"}), 401