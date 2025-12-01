import streamlit as st
import pandas as pd
from datetime import datetime
import uuid
import hashlib
import time
import re
import secrets
import string
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
import json
import os

# Adicione esta função APÓS as importações e ANTES da configuração do banco

def corrigir_senha_usuario():
    """Corrige a senha do usuário C3 Engenharia NOVAMENTE"""
    print("\n" + "="*60)
    print("🔧 CORRIGINDO SENHA DO USUÁRIO")
    print("="*60)
    
    try:
        conn = sqlite3.connect('c3_engenharia.db')
        cursor = conn.cursor()
        
        # Senha CORRETA
        SENHA_CORRETA = "462462Ca_"
        NOVO_HASH = hashlib.sha256(SENHA_CORRETA.encode()).hexdigest()
        
        print(f"📝 Senha definida: {SENHA_CORRETA}")
        print(f"🔐 Novo hash: {NOVO_HASH}")
        
        # Verificar se usuário existe
        cursor.execute("SELECT razao_social, senha_hash FROM usuarios WHERE cnpj = '12.345.678/0001-90'")
        usuario = cursor.fetchone()
        
        if usuario:
            print(f"✅ Usuário encontrado: {usuario[0]}")
            print(f"🔍 Hash atual no banco: {usuario[1]}")
            
            # Atualizar senha
            cursor.execute("""
                UPDATE usuarios 
                SET senha_hash = ?
                WHERE cnpj = '12.345.678/0001-90'
            """, (NOVO_HASH,))
            
            conn.commit()
            print("🔄 Senha ATUALIZADA no banco!")
        else:
            print("❌ Usuário não encontrado. Criando...")
            cursor.execute("""
                INSERT INTO usuarios 
                (id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo, status, data_cadastro)
                VALUES 
                ('SOL-001', 'C3 Engenharia', '12.345.678/0001-90', 
                 'caroline.frasseto@c3engenharia.com.br', '(19) 98931-4967', 
                 'Santa Bárbara D''Oeste - SP', ?, 'solicitante', 'Ativa', 
                 datetime('now'))
            """, (NOVO_HASH,))
            
            conn.commit()
            print("✅ Usuário CRIADO com nova senha!")
        
        # Verificar novamente
        cursor.execute("SELECT senha_hash FROM usuarios WHERE cnpj = '12.345.678/0001-90'")
        hash_final = cursor.fetchone()
        
        print(f"✅ Hash final no banco: {hash_final[0]}")
        print(f"✅ Hash esperado: {NOVO_HASH}")
        print(f"✅ São iguais? {hash_final[0] == NOVO_HASH}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro: {e}")
    
    print("="*60)

# Execute esta função UMA VEZ
corrigir_senha_usuario()

# =============================================
# CONFIGURAÇÃO DO BANCO DE DADOS SQLite
# =============================================
Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(String, primary_key=True)
    razao_social = Column(String(200), nullable=False)
    cnpj = Column(String(20), unique=True, nullable=False)
    email = Column(String(100), nullable=False)
    telefone = Column(String(20))
    cidade = Column(String(100))
    senha_hash = Column(String(255), nullable=False)
    tipo = Column(String(20), default='transportadora')
    status = Column(String(20), default='Ativa')
    data_cadastro = Column(DateTime, default=datetime.now)

class Solicitacao(Base):
    __tablename__ = 'solicitacoes'
    id = Column(String, primary_key=True)
    local_coleta = Column(String(200), nullable=False)
    local_entrega = Column(String(200), nullable=False)
    material = Column(String(100), nullable=False)
    valor_carga = Column(Float)
    data_coleta = Column(String(50))
    data_entrega = Column(String(50))
    tomador = Column(String(200))
    observacoes = Column(Text)
    status = Column(String(20), default='Aberta')
    usuario_id = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

class Cotacao(Base):
    __tablename__ = 'cotacoes'
    id = Column(String, primary_key=True)
    solicitacao_id = Column(String, nullable=False)
    transportadora_id = Column(String, nullable=False)
    transportadora_nome = Column(String(200), nullable=False)
    valor_frete = Column(Float, nullable=False)
    prazo_entrega = Column(String(50))
    observacoes = Column(Text)
    status = Column(String(20), default='Pendente')
    created_at = Column(DateTime, default=datetime.now)

class LogSeguranca(Base):
    __tablename__ = 'logs_seguranca'
    id = Column(Integer, primary_key=True, autoincrement=True)
    usuario_id = Column(String)
    acao = Column(String(100))
    descricao = Column(Text)
    ip = Column(String(50))
    user_agent = Column(String(200))
    created_at = Column(DateTime, default=datetime.now)

# Criar engine e tabelas
engine = create_engine('sqlite:///c3_engenharia.db', connect_args={'check_same_thread': False})
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(bind=engine))

# =============================================
# INICIALIZAÇÃO DO SISTEMA
# =============================================
def inicializar_sistema_completo():
    """Inicializa todo o sistema garantindo que o usuário padrão existe"""
    print("\n" + "="*60)
    print("🚀 INICIALIZAÇÃO DO SISTEMA")
    print("="*60)
    
    # 1. Criar tabelas se não existirem
    Base.metadata.create_all(engine)
    
    # 2. Criar usuário padrão com SQL direto (garantido)
    try:
        import sqlite3
        conn = sqlite3.connect('c3_engenharia.db')
        cursor = conn.cursor()
        
        # Verificar se usuário já existe
        cursor.execute("SELECT * FROM usuarios WHERE cnpj = '12.345.678/0001-90'")
        usuario_existente = cursor.fetchone()
        
        senha = "462462Ca_"
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()
        
        if not usuario_existente:
            print("📝 Criando usuário padrão...")
            cursor.execute("""
                INSERT INTO usuarios 
                (id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo, status, data_cadastro)
                VALUES 
                ('SOL-001', 'C3 Engenharia', '12.345.678/0001-90', 
                 'caroline.frasseto@c3engenharia.com.br', '(19) 98931-4967', 
                 'Santa Bárbara D''Oeste - SP', ?, 'solicitante', 'Ativa', 
                 datetime('now'))
            """, (senha_hash,))
            print("✅ Usuário criado!")
        else:
            print("🔄 Atualizando senha do usuário...")
            cursor.execute("""
                UPDATE usuarios 
                SET senha_hash = ?
                WHERE cnpj = '12.345.678/0001-90'
            """, (senha_hash,))
            print("✅ Senha atualizada!")
        
        conn.commit()
        
        # Verificar
        cursor.execute("SELECT razao_social, senha_hash FROM usuarios WHERE cnpj = '12.345.678/0001-90'")
        resultado = cursor.fetchone()
        
        print("✅ VERIFICAÇÃO:")
        print(f"   Usuário: {resultado[0]}")
        print(f"   Hash: {resultado[1]}")
        print(f"   Senha: {senha}")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ Erro na inicialização: {e}")
        import traceback
        traceback.print_exc()
    
    print("="*60)

# Executar inicialização
inicializar_sistema_completo()

# =============================================
# TESTE AUTOMÁTICO DE LOGIN
# =============================================
def teste_login_automatico():
    """Testa o login automaticamente para debug"""
    print("\n" + "="*60)
    print("🧪 TESTE AUTOMÁTICO DE LOGIN")
    print("="*60)
    
    # Teste com Razão Social
    usuario_nome = "C3 Engenharia"
    senha = "462462Ca_"
    
    print(f"Usuário: {usuario_nome}")
    print(f"Senha: {senha}")
    print(f"Hash esperado: {hashlib.sha256(senha.encode()).hexdigest()}")
    
    print("="*60 + "\n")

# Executar teste automático
teste_login_automatico()

# =============================================
# FUNÇÕES DO BANCO DE DADOS
# =============================================

def get_session():
    return Session()

def get_usuarios():
    session = get_session()
    try:
        usuarios = session.query(Usuario).all()
        return [{
            'id': u.id,
            'razao_social': u.razao_social,
            'cnpj': u.cnpj,
            'email': u.email,
            'telefone': u.telefone,
            'cidade': u.cidade,
            'senha_hash': u.senha_hash,
            'tipo': u.tipo,
            'status': u.status,
            'data_cadastro': u.data_cadastro.strftime('%d-%m-%Y %H:%M:%S') if u.data_cadastro else None
        } for u in usuarios]
    finally:
        session.close()

def get_usuario_por_id(usuario_id):
    session = get_session()
    try:
        usuario = session.query(Usuario).filter_by(id=usuario_id).first()
        if usuario:
            return {
                'id': usuario.id,
                'razao_social': usuario.razao_social,
                'cnpj': usuario.cnpj,
                'email': usuario.email,
                'telefone': usuario.telefone,
                'cidade': usuario.cidade,
                'senha_hash': usuario.senha_hash,
                'tipo': usuario.tipo,
                'status': usuario.status,
                'data_cadastro': usuario.data_cadastro.strftime('%d-%m-%Y %H:%M:%S') if usuario.data_cadastro else None
            }
        return None
    finally:
        session.close()

def adicionar_usuario(usuario_dict):
    session = get_session()
    try:
        usuario = Usuario(**usuario_dict)
        session.add(usuario)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def atualizar_usuario(usuario_id, dados_atualizados):
    session = get_session()
    try:
        usuario = session.query(Usuario).filter_by(id=usuario_id).first()
        if usuario:
            for key, value in dados_atualizados.items():
                if hasattr(usuario, key):
                    setattr(usuario, key, value)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def get_solicitacoes():
    session = get_session()
    try:
        solicitacoes = session.query(Solicitacao).all()
        return [{
            'id': s.id,
            'local_coleta': s.local_coleta,
            'local_entrega': s.local_entrega,
            'material': s.material,
            'valor_carga': s.valor_carga,
            'data_coleta': s.data_coleta,
            'data_entrega': s.data_entrega,
            'tomador': s.tomador,
            'observacoes': s.observacoes,
            'status': s.status,
            'usuario_id': s.usuario_id,
            'created_at': s.created_at.strftime('%d-%m-%Y %H:%M:%S') if s.created_at else None
        } for s in solicitacoes]
    finally:
        session.close()

def get_solicitacoes_por_usuario(usuario_id):
    session = get_session()
    try:
        solicitacoes = session.query(Solicitacao).filter_by(usuario_id=usuario_id).all()
        return [{
            'id': s.id,
            'local_coleta': s.local_coleta,
            'local_entrega': s.local_entrega,
            'material': s.material,
            'valor_carga': s.valor_carga,
            'data_coleta': s.data_coleta,
            'data_entrega': s.data_entrega,
            'tomador': s.tomador,
            'observacoes': s.observacoes,
            'status': s.status,
            'usuario_id': s.usuario_id,
            'created_at': s.created_at.strftime('%d-%m-%Y %H:%M:%S') if s.created_at else None
        } for s in solicitacoes]
    finally:
        session.close()

def get_solicitacao_por_id(solicitacao_id):
    session = get_session()
    try:
        solicitacao = session.query(Solicitacao).filter_by(id=solicitacao_id).first()
        if solicitacao:
            return {
                'id': solicitacao.id,
                'local_coleta': solicitacao.local_coleta,
                'local_entrega': solicitacao.local_entrega,
                'material': solicitacao.material,
                'valor_carga': solicitacao.valor_carga,
                'data_coleta': solicitacao.data_coleta,
                'data_entrega': solicitacao.data_entrega,
                'tomador': solicitacao.tomador,
                'observacoes': solicitacao.observacoes,
                'status': solicitacao.status,
                'usuario_id': solicitacao.usuario_id,
                'created_at': solicitacao.created_at.strftime('%d-%m-%Y %H:%M:%S') if solicitacao.created_at else None
            }
        return None
    finally:
        session.close()

def adicionar_solicitacao(solicitacao_dict):
    session = get_session()
    try:
        solicitacao = Solicitacao(**solicitacao_dict)
        session.add(solicitacao)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def atualizar_solicitacao(solicitacao_id, dados_atualizados):
    session = get_session()
    try:
        solicitacao = session.query(Solicitacao).filter_by(id=solicitacao_id).first()
        if solicitacao:
            for key, value in dados_atualizados.items():
                if hasattr(solicitacao, key):
                    setattr(solicitacao, key, value)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def excluir_solicitacao(solicitacao_id):
    session = get_session()
    try:
        # Primeiro excluir as cotações relacionadas
        session.query(Cotacao).filter_by(solicitacao_id=solicitacao_id).delete()
        
        # Depois excluir a solicitação
        solicitacao = session.query(Solicitacao).filter_by(id=solicitacao_id).first()
        if solicitacao:
            session.delete(solicitacao)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def get_cotacoes():
    session = get_session()
    try:
        cotacoes = session.query(Cotacao).all()
        return [{
            'id': c.id,
            'solicitacao_id': c.solicitacao_id,
            'transportadora_id': c.transportadora_id,
            'transportadora_nome': c.transportadora_nome,
            'valor_frete': c.valor_frete,
            'prazo_entrega': c.prazo_entrega,
            'observacoes': c.observacoes,
            'status': c.status,
            'created_at': c.created_at.strftime('%d-%m-%Y %H:%M:%S') if c.created_at else None
        } for c in cotacoes]
    finally:
        session.close()

def get_cotacoes_por_transportadora(transportadora_id):
    session = get_session()
    try:
        cotacoes = session.query(Cotacao).filter_by(transportadora_id=transportadora_id).all()
        return [{
            'id': c.id,
            'solicitacao_id': c.solicitacao_id,
            'transportadora_id': c.transportadora_id,
            'transportadora_nome': c.transportadora_nome,
            'valor_frete': c.valor_frete,
            'prazo_entrega': c.prazo_entrega,
            'observacoes': c.observacoes,
            'status': c.status,
            'created_at': c.created_at.strftime('%d-%m-%Y %H:%M:%S') if c.created_at else None
        } for c in cotacoes]
    finally:
        session.close()

def get_cotacoes_por_solicitacao(solicitacao_id):
    session = get_session()
    try:
        cotacoes = session.query(Cotacao).filter_by(solicitacao_id=solicitacao_id).all()
        return [{
            'id': c.id,
            'solicitacao_id': c.solicitacao_id,
            'transportadora_id': c.transportadora_id,
            'transportadora_nome': c.transportadora_nome,
            'valor_frete': c.valor_frete,
            'prazo_entrega': c.prazo_entrega,
            'observacoes': c.observacoes,
            'status': c.status,
            'created_at': c.created_at.strftime('%d-%m-%Y %H:%M:%S') if c.created_at else None
        } for c in cotacoes]
    finally:
        session.close()

def get_cotacao_por_id(cotacao_id):
    session = get_session()
    try:
        cotacao = session.query(Cotacao).filter_by(id=cotacao_id).first()
        if cotacao:
            return {
                'id': cotacao.id,
                'solicitacao_id': cotacao.solicitacao_id,
                'transportadora_id': cotacao.transportadora_id,
                'transportadora_nome': cotacao.transportadora_nome,
                'valor_frete': cotacao.valor_frete,
                'prazo_entrega': cotacao.prazo_entrega,
                'observacoes': cotacao.observacoes,
                'status': cotacao.status,
                'created_at': cotacao.created_at.strftime('%d-%m-Y %H:%M:%S') if cotacao.created_at else None
            }
        return None
    finally:
        session.close()

def adicionar_cotacao(cotacao_dict):
    session = get_session()
    try:
        cotacao = Cotacao(**cotacao_dict)
        session.add(cotacao)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def atualizar_cotacao(cotacao_id, dados_atualizados):
    session = get_session()
    try:
        cotacao = session.query(Cotacao).filter_by(id=cotacao_id).first()
        if cotacao:
            for key, value in dados_atualizados.items():
                if hasattr(cotacao, key):
                    setattr(cotacao, key, value)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def excluir_cotacao(cotacao_id):
    session = get_session()
    try:
        cotacao = session.query(Cotacao).filter_by(id=cotacao_id).first()
        if cotacao:
            session.delete(cotacao)
            session.commit()
            return True
        return False
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

def adicionar_log_seguranca(log_dict):
    session = get_session()
    try:
        log = LogSeguranca(**log_dict)
        session.add(log)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

# =============================================
# FUNÇÕES DE VALIDAÇÃO E SEGURANÇA
# =============================================

def validar_cnpj(cnpj):
    """Valida formato de CNPJ"""
    cnpj = re.sub(r'[^0-9]', '', str(cnpj))
    return len(cnpj) == 14

def validar_email(email):
    """Valida formato de e-mail"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validar_telefone(telefone):
    """Valida formato de telefone"""
    telefone = re.sub(r'[^0-9]', '', str(telefone))
    return len(telefone) >= 10 and len(telefone) <= 11

def validar_senha_forte(senha):
    """Valida força da senha"""
    if len(senha) < 8:
        return False, "A senha deve ter pelo menos 8 caracteres"
    
    if not any(c.isupper() for c in senha):
        return False, "A senha deve ter pelo menos uma letra maiúscula"
    
    if not any(c.islower() for c in senha):
        return False, "A senha deve ter pelo menos uma letra minúscula"
    
    if not any(c.isdigit() for c in senha):
        return False, "A senha deve ter pelo menos um número"
    
    if not any(c in string.punctuation for c in senha):
        return False, "A senha deve ter pelo menos um caractere especial"
    
    return True, "Senha forte"

def gerar_senha_temporaria():
    """Gera senha temporária forte"""
    caracteres = string.ascii_letters + string.digits + "!@#$%&*"
    return ''.join(secrets.choice(caracteres) for _ in range(12))

def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

# FUNÇÕES PARA DATAS EM PT-BR - CORRIGIDAS
def data_ptbr(data_str):
    """Converte data do banco para formato PT-BR"""
    try:
        if data_str is None:
            return "Data não disponível"
            
        if isinstance(data_str, str):
            try:
                data_obj = datetime.strptime(data_str, '%d-%m-%Y %H:%M:%S')
            except ValueError:
                try:
                    data_obj = datetime.strptime(data_str, '%d-%m-%Y')
                except ValueError:
                    return str(data_str)
        else:
            data_obj = data_str
        
        return data_obj.strftime('%d/%m/%Y às %H:%M')
    except Exception as e:
        return str(data_str)

def data_agora_brasilia():
    """Retorna data/hora atual no fuso do Brasil"""
    return datetime.now()

def tempo_desde(data_str):
    """Calcula tempo passado desde uma data (em PT-BR)"""
    try:
        if data_str is None:
            return "tempo desconhecido"
            
        if isinstance(data_str, str):
            try:
                data_obj = datetime.strptime(data_str, '%d-%m-%Y %H:%M:%S')
            except ValueError:
                try:
                    data_obj = datetime.strptime(data_str, '%d-%m-%Y')
                except ValueError:
                    return "tempo desconhecido"
        else:
            data_obj = data_str
        
        agora = datetime.now()
        diferenca = agora - data_obj
        
        segundos = int(diferenca.total_seconds())
        minutos = int(segundos / 60)
        horas = int(minutos / 60)
        dias = int(horas / 24)
        
        if segundos < 60:
            return "agora mesmo"
        elif minutos < 60:
            return f"{minutos} min atrás" if minutos > 1 else "1 min atrás"
        elif horas < 24:
            return f"{horas} h atrás" if horas > 1 else "1 h atrás"
        elif dias == 1:
            return "1 dia atrás"
        else:
            return f"{dias} dias atrás"
    except:
        return "tempo desconhecido"

# =============================================
# FUNÇÃO DE LOGIN SIMPLIFICADA
# =============================================

def verificar_login(usuario_input, senha):
    """Verifica login - VERSÃO SUPER SIMPLES"""
    if not usuario_input or not senha:
        st.error("Preencha todos os campos")
        return None
    
    print(f"\n" + "="*40)
    print(f"🔍 TENTATIVA DE LOGIN")
    print(f"Usuário digitado: {usuario_input}")
    print(f"Senha digitada: {senha}")
    
    try:
        # Conectar ao banco
        conn = sqlite3.connect('c3_engenharia.db')
        cursor = conn.cursor()
        
        # BUSCAR USUÁRIO
        usuario = None
        
        # Tentar por "C3 Engenharia" (razão social)
        cursor.execute("SELECT * FROM usuarios WHERE LOWER(razao_social) = LOWER(?)", (usuario_input,))
        usuario = cursor.fetchone()
        
        # Se não encontrou, tentar por CNPJ
        if not usuario:
            cursor.execute("SELECT * FROM usuarios WHERE cnpj = ?", (usuario_input,))
            usuario = cursor.fetchone()
        
        if usuario:
            print(f"✅ USUÁRIO ENCONTRADO:")
            print(f"   ID: {usuario[0]}")
            print(f"   Razão Social: {usuario[1]}")
            print(f"   CNPJ: {usuario[2]}")
            print(f"   Hash no banco: {usuario[6]}")
            
            # Calcular hash da senha digitada
            senha_hash_digitada = hashlib.sha256(senha.encode()).hexdigest()
            print(f"🔐 Hash da senha digitada: {senha_hash_digitada}")
            print(f"🔐 Hash no banco: {usuario[6]}")
            print(f"✅ São iguais? {senha_hash_digitada == usuario[6]}")
            
            # VERIFICAR SENHA
            if senha_hash_digitada == usuario[6]:
                print("🎉 LOGIN BEM-SUCEDIDO!")
                conn.close()
                
                return {
                    'id': usuario[0],
                    'razao_social': usuario[1],
                    'cnpj': usuario[2],
                    'email': usuario[3],
                    'telefone': usuario[4],
                    'cidade': usuario[5],
                    'senha_hash': usuario[6],
                    'tipo': usuario[7],
                    'status': usuario[8],
                    'data_cadastro': usuario[9]
                }
            else:
                print("❌ SENHA INCORRETA")
                print(f"   Hash esperado: {usuario[6]}")
                print(f"   Hash recebido: {senha_hash_digitada}")
        else:
            print("❌ USUÁRIO NÃO ENCONTRADO")
        
        conn.close()
        
    except Exception as e:
        print(f"❌ ERRO: {e}")
        import traceback
        traceback.print_exc()
    
    return None

def cadastrar_usuario(razao_social, cnpj, email, telefone, cidade, senha, tipo='transportadora'):
    try:
        session = get_session()
        
        # Verificar se CNPJ já existe
        usuario_existente = session.query(Usuario).filter_by(cnpj=cnpj).first()
        if usuario_existente:
            return False
        
        usuario_id = f"USER-{uuid.uuid4().hex[:8].upper()}"
        senha_hash = hash_senha(senha)
        
        usuario_dict = {
            'id': usuario_id,
            'razao_social': razao_social,
            'cnpj': cnpj,
            'email': email,
            'telefone': telefone,
            'cidade': cidade,
            'senha_hash': senha_hash,
            'tipo': tipo,
            'status': 'Ativa',
            'data_cadastro': datetime.now()
        }
        
        success = adicionar_usuario(usuario_dict)
        
        if success:
            adicionar_log_seguranca({
                'usuario_id': 'SISTEMA',
                'acao': 'CADASTRO_USUARIO',
                'descricao': f'Novo usuário: {razao_social}',
                'ip': 'N/A',
                'user_agent': 'N/A',
                'created_at': datetime.now()
            })
            return True
        return False
        
    except Exception as e:
        st.error(f"Erro ao cadastrar usuário: {e}")
        return False

# =============================================
# FUNÇÕES DO SISTEMA
# =============================================

def get_estatisticas_solicitante(usuario_id):
    solicitacoes = get_solicitacoes_por_usuario(usuario_id)
    usuarios = get_usuarios()
    cotacoes = get_cotacoes()
    
    hoje = datetime.now().strftime('%d-%m-%Y')
    
    solicitacoes_ativas = sum(1 for s in solicitacoes if s.get('status') == 'Aberta')
    total_transportadoras = sum(1 for u in usuarios if u.get('tipo') == 'transportadora' and u.get('status') == 'Ativa')
    
    # Total de cotações das minhas solicitações
    total_cotacoes = 0
    for sol in solicitacoes:
        cotacoes_solicitacao = get_cotacoes_por_solicitacao(sol['id'])
        total_cotacoes += len(cotacoes_solicitacao)
    
    # Cotações hoje
    cotacoes_hoje = 0
    for cot in cotacoes:
        if cot.get('created_at', '').startswith(hoje):
            # Verificar se a solicitação pertence ao usuário
            solicitacao = get_solicitacao_por_id(cot.get('solicitacao_id'))
            if solicitacao and solicitacao.get('usuario_id') == usuario_id:
                cotacoes_hoje += 1
    
    return {
        'solicitacoes_ativas': solicitacoes_ativas,
        'total_transportadoras': total_transportadoras,
        'total_cotacoes': total_cotacoes,
        'cotacoes_hoje': cotacoes_hoje
    }

def get_estatisticas_transportadora(transportadora_id):
    cotacoes = get_cotacoes_por_transportadora(transportadora_id)
    
    total_cotacoes = len(cotacoes)
    cotacoes_aceitas = sum(1 for cot in cotacoes if cot.get('status') == 'Aceita')
    cotacoes_pendentes = sum(1 for cot in cotacoes if cot.get('status') == 'Pendente')
    cotacoes_recusadas = sum(1 for cot in cotacoes if cot.get('status') == 'Recusada')
    
    return {
        'total_cotacoes': total_cotacoes,
        'cotacoes_aceitas': cotacoes_aceitas,
        'cotacoes_pendentes': cotacoes_pendentes,
        'cotacoes_recusadas': cotacoes_recusadas
    }

# =============================================
# CONFIGURAÇÃO DO STREAMLIT
# =============================================
st.set_page_config(page_title="Sistema de Cotações C3 Engenharia", page_icon="🌐", layout="wide")

# CSS PROFISSIONAL E SOBRIO
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');
    
    * {
        font-family: 'Inter', sans-serif;
    }
    
    .main-header { 
        font-size: 1.8rem; 
        color: #1a365d; 
        text-align: center; 
        margin-bottom: 2rem; 
        font-weight: 600;
        border-bottom: 2px solid #2e86ab;
        padding-bottom: 1rem;
    }
    .metric-card { 
        background: #f8f9fa; 
        color: #2d3748; 
        padding: 1.5rem; 
        border-radius: 8px; 
        text-align: center;
        border-left: 4px solid #2e86ab;
        margin-bottom: 1rem;
        font-weight: 500;
    }
    .danger-zone { 
        background-color: #fff5f5; 
        padding: 1rem; 
        border-radius: 6px; 
        border: 1px solid #fed7d7; 
    }
    .card-profissional {
        background: white;
        padding: 1.5rem;
        border-radius: 6px;
        border: 1px solid #e2e8f0;
        margin-bottom: 1rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
    }
    .stButton button {
        font-weight: 500;
        border-radius: 6px;
    }
    .success-status {
        color: #10b981;
        font-weight: 600;
    }
    .pending-status {
        color: #f59e0b;
        font-weight: 600;
    }
    .rejected-status {
        color: #ef4444;
        font-weight: 600;
    }
    .security-warning {
        background-color: #fffbeb;
        border: 1px solid #f59e0b;
        border-radius: 6px;
        padding: 1rem;
        margin: 1rem 0;
    }
    .blue-emoji {
        color: #2e86ab;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# =============================================
# SISTEMA DE LOGIN
# =============================================

def mostrar_login():
    st.markdown('<div class="main-header">SISTEMA DE COTAÇÕES - C3 ENGENHARIA</div>', unsafe_allow_html=True)
    
    tab1, tab2 = st.tabs(["Login", "Cadastro Transportadoras"])
    
    with tab1:
        st.markdown("### Acesso ao Sistema")
        
        # AVISO DE SEGURANÇA
        st.markdown("""
        <div class="security-warning">
            <strong>AVISO DE SEGURANÇA:</strong><br>
            • Não compartilhe suas credenciais<br>
            • Use senhas fortes e únicas<br>
            • Desconecte-se ao terminar
        </div>
        """, unsafe_allow_html=True)
        
        with st.form("login_form"):
            usuario_input = st.text_input("Usuário (CNPJ ou Razão Social)", placeholder="Digite 'C3 Engenharia'")
            senha = st.text_input("Senha", type="password", placeholder="Digite sua senha")
            submit_login = st.form_submit_button("Entrar no Sistema")
            
            if submit_login:
                if usuario_input and senha:
                    with st.spinner("Verificando credenciais..."):
                        usuario = verificar_login(usuario_input, senha)
                        if usuario:
                            st.session_state.logged_in = True
                            st.session_state.usuario_id = usuario['id']
                            st.session_state.razao_social = usuario['razao_social']
                            st.session_state.tipo_usuario = usuario['tipo']
                            st.success(f"Bem-vindo, {usuario['razao_social']}!")
                            time.sleep(1)
                            st.rerun()
                        else:
                            st.error("Usuário ou senha incorretos. Tente: Usuário: 'C3 Engenharia', Senha: '462462Ca_'")
                else:
                    st.error("Preencha todos os campos")
    
    with tab2:
        st.markdown("### Cadastro de Transportadoras")
        st.warning("ÁREA EXCLUSIVA PARA TRANSPORTADORAS")
        st.info("Solicitantes: Use o login da C3 Engenharia")
        
        with st.form("cadastro_form"):
            razao_social = st.text_input("Razão Social*", max_chars=100)
            cnpj = st.text_input("CNPJ*", placeholder="00.000.000/0000-00", max_chars=18)
            email = st.text_input("E-mail*", max_chars=100)
            telefone = st.text_input("Telefone*", placeholder="(11) 99999-9999", max_chars=15)
            cidade = st.text_input("Cidade/UF*", placeholder="São Paulo - SP", max_chars=50)
            senha = st.text_input("Senha*", type="password", 
                                 help="Mínimo 8 caracteres, com letras maiúsculas, minúsculas, números e símbolos")
            confirmar_senha = st.text_input("Confirmar Senha*", type="password")
            
            submit_cadastro = st.form_submit_button("Cadastrar Transportadora")
            
            if submit_cadastro:
                # VALIDAÇÕES DE SEGURANÇA
                erros = []
                
                if not all([razao_social, cnpj, email, telefone, cidade, senha, confirmar_senha]):
                    erros.append("Preencha todos os campos")
                
                if not validar_cnpj(cnpj):
                    erros.append("CNPJ inválido")
                
                if not validar_email(email):
                    erros.append("E-mail inválido")
                
                if not validar_telefone(telefone):
                    erros.append("Telefone inválido")
                
                senha_valida, msg_senha = validar_senha_forte(senha)
                if not senha_valida:
                    erros.append(msg_senha)
                
                if senha != confirmar_senha:
                    erros.append("As senhas não coincidem")
                
                if erros:
                    for erro in erros:
                        st.error(erro)
                else:
                    if cadastrar_usuario(razao_social, cnpj, email, telefone, cidade, senha, 'transportadora'):
                        st.success("Transportadora cadastrada com sucesso! ✅")
                        st.info("Acesso liberado imediatamente para cadastro de cotações.")
                    else:
                        st.error("CNPJ já cadastrado no sistema")

# =============================================
# VERIFICAÇÕES DE SEGURANÇA
# =============================================

if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    # =============================================
    # TESTE DIRETO DE LOGIN (SIDEBAR)
    # =============================================
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 🧪 TESTE DIRETO DE LOGIN")
    
    with st.sidebar.form("teste_login_direto"):
        st.write("**Credenciais de Teste:**")
        st.code("Usuário: C3 Engenharia\nSenha: 462462Ca_")
        
        usuario_teste = st.text_input("Usuário", value="C3 Engenharia", key="teste_usuario")
        senha_teste = st.text_input("Senha", type="password", value="462462Ca_", key="teste_senha")
        
        col1, col2 = st.columns(2)
        with col1:
            testar_btn = st.form_submit_button("🧪 Testar", use_container_width=True)
        with col2:
            entrar_btn = st.form_submit_button("🚪 Entrar", use_container_width=True)
        
        if testar_btn or entrar_btn:
            with st.spinner("Testando login..."):
                resultado = verificar_login(usuario_teste, senha_teste)
                if resultado:
                    st.success(f"✅ Login funciona! Usuário: {resultado['razao_social']}")
                    
                    # Se clicou em "Entrar", faz login automaticamente
                    if entrar_btn:
                        st.session_state.logged_in = True
                        st.session_state.usuario_id = resultado['id']
                        st.session_state.razao_social = resultado['razao_social']
                        st.session_state.tipo_usuario = resultado['tipo']
                        time.sleep(1)
                        st.rerun()
                else:
                    st.error("❌ Login falhou!")
                    st.info("Verifique o console para detalhes")
    
st.sidebar.markdown("---")
st.sidebar.markdown("### 🛠️ FERRAMENTAS")

# BOTÃO 1: Recriar Banco
if st.sidebar.button("🔄 Recriar Banco de Dados", type="secondary", use_container_width=True):
    try:
        import os
        if os.path.exists('c3_engenharia.db'):
            os.remove('c3_engenharia.db')
            st.sidebar.success("✅ Banco removido!")
        
        # Recriar todas as tabelas
        Base.metadata.create_all(engine)
        
        # Criar usuário correto
        conn = sqlite3.connect('c3_engenharia.db')
        cursor = conn.cursor()
        
        senha = "462462Ca_"
        senha_hash = hashlib.sha256(senha.encode()).hexdigest()
        
        print(f"\n🔧 CRIANDO NOVO USUÁRIO:")
        print(f"   Senha: {senha}")
        print(f"   Hash: {senha_hash}")
        
        cursor.execute("""
            INSERT OR REPLACE INTO usuarios 
            (id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo, status, data_cadastro)
            VALUES 
            ('SOL-001', 'C3 Engenharia', '12.345.678/0001-90', 
             'caroline.frasseto@c3engenharia.com.br', '(19) 98931-4967', 
             'Santa Bárbara D''Oeste - SP', ?, 'solicitante', 'Ativa', 
             datetime('now'))
        """, (senha_hash,))
        
        conn.commit()
        
        # Verificar
        cursor.execute("SELECT razao_social, senha_hash FROM usuarios WHERE cnpj = '12.345.678/0001-90'")
        resultado = cursor.fetchone()
        
        conn.close()
        
        st.sidebar.success("✅ Banco recriado com sucesso!")
        st.sidebar.info(f"**Usuário:** C3 Engenharia")
        st.sidebar.info(f"**Senha:** {senha}")
        st.sidebar.info(f"**Hash:** {senha_hash}")
        
        # Resetar sessão
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        
        st.rerun()
        
    except Exception as e:
        st.sidebar.error(f"❌ Erro: {e}")

# BOTÃO 2: Reset de Emergência (ADICIONE ESTE NOVO BOTÃO)
if st.sidebar.button("🚨 Reset de Emergência (Login)", type="primary", use_container_width=True):
    with st.spinner("Corrigindo problema de login..."):
        try:
            conn = sqlite3.connect('c3_engenharia.db')
            cursor = conn.cursor()
            
            # Senha CORRETA
            SENHA = "462462Ca_"
            HASH_CORRETO = hashlib.sha256(SENHA.encode()).hexdigest()
            
            print(f"\n🚨 RESET DE EMERGÊNCIA:")
            print(f"   Senha definida: {SENHA}")
            print(f"   Hash correto: {HASH_CORRETO}")
            
            # Verificar se usuário existe
            cursor.execute("SELECT razao_social, senha_hash FROM usuarios WHERE cnpj = '12.345.678/0001-90' OR razao_social = 'C3 Engenharia'")
            usuario = cursor.fetchone()
            
            if usuario:
                print(f"   Usuário encontrado: {usuario[0]}")
                print(f"   Hash antigo: {usuario[1]}")
                
                # Atualizar senha
                cursor.execute("""
                    UPDATE usuarios 
                    SET senha_hash = ?
                    WHERE cnpj = '12.345.678/0001-90' OR razao_social = 'C3 Engenharia'
                """, (HASH_CORRETO,))
                
                st.sidebar.success(f"✅ Senha resetada: {SENHA}")
            else:
                # Criar usuário
                cursor.execute("""
                    INSERT INTO usuarios 
                    (id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo, status, data_cadastro)
                    VALUES 
                    ('SOL-001', 'C3 Engenharia', '12.345.678/0001-90', 
                     'caroline.frasseto@c3engenharia.com.br', '(19) 98931-4967', 
                     'Santa Bárbara D''Oeste - SP', ?, 'solicitante', 'Ativa', 
                     datetime('now'))
                """, (HASH_CORRETO,))
                
                st.sidebar.success(f"✅ Usuário criado com senha: {SENHA}")
            
            conn.commit()
            
            # Testar login automaticamente
            cursor.execute("SELECT senha_hash FROM usuarios WHERE razao_social = 'C3 Engenharia'")
            hash_final = cursor.fetchone()
            
            conn.close()
            
            st.sidebar.info(f"🔐 Hash final: {hash_final[0]}")
            st.sidebar.success("🔄 Tente fazer login novamente!")
            
        except Exception as e:
            st.sidebar.error(f"❌ Erro no reset: {e}")

st.sidebar.markdown("---")

# =============================================
# SISTEMA PRINCIPAL (APÓS LOGIN)
# =============================================

# HEADER PERSONALIZADO
st.markdown(f"""
<div class="main-header">
   <span class="blue-emoji">🌐</span> SISTEMA DE COTAÇÕES | {st.session_state.razao_social}
</div>
""", unsafe_allow_html=True)

# SIDEBAR PERSONALIZADA
with st.sidebar:
    st.markdown(f"### 👤 {st.session_state.razao_social}")
    st.markdown(f"**Tipo:** {'Solicitante' if st.session_state.tipo_usuario == 'solicitante' else 'Transportadora'}")
    st.markdown("---")
    
    # MENU DINÂMICO BASEADO NO TIPO DE USUÁRIO
    if st.session_state.tipo_usuario == 'solicitante':
        menu_options = [
            "Dashboard", 
            "Nova Solicitação", 
            "Gerenciar Solicitações",
            "Cotações Recebidas",
            "Transportadoras Cadastradas",
            "Backup de Dados",
            "Meu Perfil"
        ]
    else:
        menu_options = [
            "Dashboard", 
            "Fretes Disponíveis", 
            "Minhas Cotações",
            "Meu Perfil"
        ]
    
    menu = st.radio("MENU PRINCIPAL", menu_options)
    st.markdown("---")
    
    # BOTÃO DE LOGOUT SEGURO
    if st.button("Sair do Sistema", use_container_width=True):
        adicionar_log_seguranca({
            'usuario_id': st.session_state.usuario_id,
            'acao': 'LOGOUT',
            'descricao': 'Usuário desconectado',
            'ip': 'N/A',
            'user_agent': 'N/A',
            'created_at': datetime.now()
        })
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# =============================================
# DASHBOARD DINÂMICO
# =============================================
if menu == "Dashboard":
    
    if st.session_state.tipo_usuario == 'solicitante':
        with st.spinner("Atualizando dados..."):
            time.sleep(0.5)
            stats = get_estatisticas_solicitante(st.session_state.usuario_id)
        
        st.markdown(f"### Bem-vindo, {st.session_state.razao_social}!")
        
        # MÉTRICAS ATUALIZADAS
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f'<div class="metric-card">Solicitações Ativas<br><h3>{stats["solicitacoes_ativas"]}</h3></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card">Transportadoras<br><h3>{stats["total_transportadoras"]}</h3></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card">Cotações Recebidas<br><h3>{stats["total_cotacoes"]}</h3></div>', unsafe_allow_html=True)
        with col4:
            st.markdown(f'<div class="metric-card">Cotações Hoje<br><h3>{stats["cotacoes_hoje"]}</h3></div>', unsafe_allow_html=True)
        
        if st.button("Atualizar Dados"):
            st.rerun()
        
        st.markdown("---")
        
        # ATIVIDADE RECENTE
        st.markdown("### Atividade Recente")
        
        try:
            solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
            ultimas_cotacoes = []
            
            for sol in solicitacoes[:5]:  # Últimas 5 solicitações
                cotacoes_sol = get_cotacoes_por_solicitacao(sol['id'])
                for cot in cotacoes_sol[:2]:  # Últimas 2 cotações por solicitação
                    ultimas_cotacoes.append({
                        'id': cot['id'],
                        'transportadora_nome': cot['transportadora_nome'],
                        'valor_frete': cot['valor_frete'],
                        'prazo_entrega': cot['prazo_entrega'],
                        'created_at': cot['created_at'],
                        'local_coleta': sol['local_coleta'],
                        'local_entrega': sol['local_entrega']
                    })
            
            # Ordenar por data mais recente
            ultimas_cotacoes.sort(key=lambda x: x['created_at'], reverse=True)
            ultimas_cotacoes = ultimas_cotacoes[:5]
            
            if ultimas_cotacoes:
                st.markdown("#### Últimas Cotações Recebidas")
                for cot in ultimas_cotacoes:
                    tempo = tempo_desde(cot['created_at'])
                    valor_frete = float(cot['valor_frete']) if cot['valor_frete'] else 0
                    st.info(f"**{cot['transportadora_nome']}** - R$ {valor_frete:,.2f} - {cot['local_coleta']} → {cot['local_entrega']} - {tempo}")
            else:
                st.info("Nenhuma cotação recebida ainda")
        except Exception as e:
            st.info("Nenhuma cotação recebida ainda")
            
    else:
        # Dashboard para Transportadora
        st.markdown(f"### Dashboard - {st.session_state.razao_social}")
        
        stats = get_estatisticas_transportadora(st.session_state.usuario_id)
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.markdown(f'<div class="metric-card">Cotações Enviadas<br><h3>{stats["total_cotacoes"]}</h3></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card">Cotações Aceitas<br><h3>{stats["cotacoes_aceitas"]}</h3></div>', unsafe_allow_html=True)
        with col3:
            st.markdown(f'<div class="metric-card">Cotações Pendentes<br><h3>{stats["cotacoes_pendentes"]}</h3></div>', unsafe_allow_html=True)
        with col4:
            taxa_sucesso = (stats["cotacoes_aceitas"] / stats["total_cotacoes"] * 100) if stats["total_cotacoes"] > 0 else 0
            st.markdown(f'<div class="metric-card">Taxa de Sucesso<br><h3>{taxa_sucesso:.1f}%</h3></div>', unsafe_allow_html=True)

# =============================================
# NOVA SOLICITAÇÃO (APENAS SOLICITANTE)
# =============================================
elif menu == "Nova Solicitação" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Nova Solicitação de Frete")
    
    with st.form("nova_solicitacao"):
        col1, col2 = st.columns(2)
        
        with col1:
            local_coleta = st.text_input("Local de Coleta*", placeholder="Ex: Piracicaba - SP")
            material = st.selectbox("Material*", ["Eletrônicos", "Móveis", "Alimentos", "Químicos", "Automotivo", "Metais", "Plásticos", "Papel"])
            data_coleta = st.date_input("Data Coleta*", min_value=datetime.today())
            
        with col2:
            local_entrega = st.text_input("Local de Entrega*", placeholder="Ex: Salvador - BA")
            valor_carga = st.number_input("Valor da Carga (R$)*", min_value=0.0, format="%.2f")
            data_entrega = st.date_input("Data Entrega*", min_value=datetime.today())
        
        tomador = st.text_input("Tomador*", placeholder="Cliente final", value="C3 Engenharia")
        observacoes = st.text_area("Observações", placeholder="Informações adicionais sobre a carga...")
        
        submitted = st.form_submit_button("Publicar Solicitação")
        
        if submitted:
            if all([local_coleta, local_entrega, material, tomador]):
                solicitacao_id = f"FRT-{data_agora_brasilia().strftime('%Y%m%d-%H%M%S')}"
                
                solicitacao_dict = {
                    'id': solicitacao_id,
                    'local_coleta': local_coleta,
                    'local_entrega': local_entrega,
                    'material': material,
                    'valor_carga': valor_carga,
                    'data_coleta': data_coleta.strftime('%Y-%m-%d'),
                    'data_entrega': data_entrega.strftime('%Y-%m-%d'),
                    'tomador': tomador,
                    'observacoes': observacoes,
                    'status': 'Aberta',
                    'usuario_id': st.session_state.usuario_id,
                    'created_at': datetime.now()
                }
                
                if adicionar_solicitacao(solicitacao_dict):
                    st.success(f"Solicitação {solicitacao_id} publicada com sucesso!")
                    adicionar_log_seguranca({
                        'usuario_id': st.session_state.usuario_id,
                        'acao': 'NOVA_SOLICITACAO',
                        'descricao': f'Solicitação: {solicitacao_id}',
                        'ip': 'N/A',
                        'user_agent': 'N/A',
                        'created_at': datetime.now()
                    })
                else:
                    st.error("Erro ao publicar solicitação")
            else:
                st.error("Preencha todos os campos obrigatórios")

# =============================================
# GERENCIAR SOLICITAÇÕES (COM EXCLUSÃO)
# =============================================
elif menu == "Gerenciar Solicitações" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Gerenciar Solicitações")
    
    try:
        minhas_solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        minhas_solicitacoes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        if minhas_solicitacoes:
            for sol in minhas_solicitacoes:
                with st.expander(f"{sol.get('id', '')} - {sol.get('local_coleta', '')} → {sol.get('local_entrega', '')} - {sol.get('status', '')}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Material:** {sol.get('material', '')}")
                        st.markdown(f"**Valor da Carga:** R$ {float(sol.get('valor_carga', 0)):,.2f}" if sol.get('valor_carga') else "**Valor da Carga:** Não informado")
                        st.markdown(f"**Data Coleta:** {sol.get('data_coleta', '')}")
                        st.markdown(f"**Tomador:** {sol.get('tomador', '')}")
                    
                    with col2:
                        st.markdown(f"**Data Entrega:** {sol.get('data_entrega', '')}")
                        st.markdown(f"**Status:** {sol.get('status', '')}")
                        st.markdown(f"**Criada em:** {data_ptbr(sol.get('created_at', ''))}")
                        st.markdown(f"**Observações:** {sol.get('observacoes', '') if sol.get('observacoes') else 'Nenhuma'}")
                    
                    # CONTAR COTAÇÕES
                    cotacoes_sol = get_cotacoes_por_solicitacao(sol.get('id', ''))
                    st.markdown(f"**Cotações recebidas:** {len(cotacoes_sol)}")
                    
                    st.markdown("---")
                    st.markdown("#### Excluir Solicitação")
                    
                    with st.form(f"excluir_sol_{sol.get('id', '')}"):
                        st.markdown('<div class="danger-zone">', unsafe_allow_html=True)
                        st.error("ATENÇÃO: Esta ação não pode ser desfeita!")
                        st.write("Serão excluídos:")
                        st.write("- Esta solicitação")
                        st.write("- Todas as cotações relacionadas")
                        
                        confirmar = st.checkbox("Confirmar exclusão permanente", key=f"confirm_{sol.get('id', '')}")
                        confirmar2 = st.checkbox("Estou ciente que esta ação é irreversível", key=f"confirm2_{sol.get('id', '')}")
                        
                        if st.form_submit_button("EXCLUIR SOLICITAÇÃO", 
                                               disabled=not (confirmar and confirmar2),
                                               type="secondary"):
                            try:
                                if excluir_solicitacao(sol.get('id', '')):
                                    st.success("Solicitação excluída com sucesso!")
                                    adicionar_log_seguranca({
                                        'usuario_id': st.session_state.usuario_id,
                                        'acao': 'EXCLUIR_SOLICITACAO',
                                        'descricao': f'Solicitação ID: {sol.get("id", "")}',
                                        'ip': 'N/A',
                                        'user_agent': 'N/A',
                                        'created_at': datetime.now()
                                    })
                                    time.sleep(2)
                                    st.rerun()
                                else:
                                    st.error("Erro ao excluir solicitação")
                            except Exception as e:
                                st.error(f"Erro ao excluir: {str(e)}")
                        st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("Nenhuma solicitação criada ainda")
    except Exception as e:
        st.error(f"Erro ao carregar solicitações: {e}")
        st.info("Tente recarregar a página")

# =============================================
# COTAÇÕES RECEBIDAS (COM EXCLUSÃO)
# =============================================
elif menu == "Cotações Recebidas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Cotações Recebidas")
    
    try:
        minhas_solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        todas_cotacoes = get_cotacoes()
        
        # Filtrar cotações das minhas solicitações
        minhas_cotacoes = []
        for cot in todas_cotacoes:
            for sol in minhas_solicitacoes:
                if sol.get('id') == cot.get('solicitacao_id'):
                    minhas_cotacoes.append({
                        **cot,
                        'local_coleta': sol.get('local_coleta'),
                        'local_entrega': sol.get('local_entrega'),
                        'material': sol.get('material'),
                        'valor_carga': sol.get('valor_carga')
                    })
                    break
        
        minhas_cotacoes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        if minhas_cotacoes:
            # Estatísticas
            total_cotacoes = len(minhas_cotacoes)
            cotacoes_aceitas = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Aceita")
            cotacoes_pendentes = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Pendente")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total de Cotações", total_cotacoes)
            with col2:
                st.metric("Cotações Pendentes", cotacoes_pendentes)
            with col3:
                st.metric("Cotações Aceitas", cotacoes_aceitas)
            
            st.markdown("---")
            
            for i, cot in enumerate(minhas_cotacoes):
                # Definir estilo baseado no status
                if cot.get('status') == "Aceita":
                    status_emoji = "✅"
                    border_color = "4px solid #10b981"
                elif cot.get('status') == "Recusada":
                    status_emoji = "❌"
                    border_color = "4px solid #ef4444"
                else:
                    status_emoji = "⏳"
                    border_color = "4px solid #3b82f6"
                
                valor_frete = float(cot.get('valor_frete', 0)) if cot.get('valor_frete') else 0
                
                with st.expander(f"{status_emoji} {cot.get('id', '')} - {cot.get('local_coleta', '')} → {cot.get('local_entrega', '')} - R$ {valor_frete:,.2f}", expanded=False):
                    # Card com borda colorida
                    st.markdown(f"""
                    <div style="border-left: {border_color}; padding-left: 1rem; margin-bottom: 1rem;">
                        <h4>Cotação {cot.get('id', '')} - Status: {cot.get('status', '')}</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.markdown("**Informações da Transportadora**")
                        st.markdown(f"**Empresa:** {cot.get('transportadora_nome', '')}")
                        st.markdown(f"**Solicitação:** {cot.get('solicitacao_id', '')}")
                        st.markdown(f"**Material:** {cot.get('material', '')}")
                        valor_carga = float(cot.get('valor_carga', 0)) if cot.get('valor_carga') else 0
                        st.markdown(f"**Valor da Carga:** R$ {valor_carga:,.2f}")
                    
                    with col2:
                        st.markdown("**Detalhes da Cotação**")
                        st.markdown(f"**Valor do Frete:** R$ {valor_frete:,.2f}")
                        st.markdown(f"**Prazo:** {cot.get('prazo_entrega', '')}")
                        st.markdown(f"**Status:** {cot.get('status', '')}")
                        st.markdown(f"**Enviada em:** {data_ptbr(cot.get('created_at', ''))}")
                    
                    with col3:
                        st.markdown("**Observações**")
                        st.markdown(f"**Observações:** {cot.get('observacoes', '') if cot.get('observacoes') else 'Nenhuma'}")
                        
                        # BOTÕES DE AÇÃO
                        st.markdown("**Ações Rápidas**")
                        
                        if cot.get('status') == "Pendente":
                            col_aceitar, col_recusar = st.columns(2)
                            with col_aceitar:
                                if st.button("Aceitar", key=f"aceitar_{cot.get('id', '')}_{i}", use_container_width=True):
                                    if atualizar_cotacao(cot.get('id', ''), {'status': 'Aceita'}):
                                        st.success("Cotação aceita com sucesso!")
                                        adicionar_log_seguranca({
                                            'usuario_id': st.session_state.usuario_id,
                                            'acao': 'COTACAO_ACEITA',
                                            'descricao': f'Cotação ID: {cot.get("id", "")}',
                                            'ip': 'N/A',
                                            'user_agent': 'N/A',
                                            'created_at': datetime.now()
                                        })
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("Erro ao aceitar cotação")
                            
                            with col_recusar:
                                if st.button("Recusar", key=f"recusar_{cot.get('id', '')}_{i}", use_container_width=True):
                                    if atualizar_cotacao(cot.get('id', ''), {'status': 'Recusada'}):
                                        st.error("Cotação recusada!")
                                        adicionar_log_seguranca({
                                            'usuario_id': st.session_state.usuario_id,
                                            'acao': 'COTACAO_RECUSADA',
                                            'descricao': f'Cotação ID: {cot.get("id", "")}',
                                            'ip': 'N/A',
                                            'user_agent': 'N/A',
                                            'created_at': datetime.now()
                                        })
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("Erro ao recusar cotação")
                        else:
                            st.info(f"Cotação já {cot.get('status', '').lower()}")
                    
                    # EXCLUSÃO DE COTAÇÃO
                    st.markdown("---")
                    st.markdown("#### Excluir Cotação")
                    
                    with st.form(f"excluir_cot_{cot.get('id', '')}_{i}"):
                        st.warning("**ATENÇÃO:** Esta ação não pode ser desfeita. A cotação será removida permanentemente do sistema.")
                        
                        confirmar1 = st.checkbox("Entendo que esta ação é permanente", key=f"confirm1_{cot.get('id', '')}_{i}")
                        confirmar2 = st.checkbox("Desejo realmente excluir esta cotação", key=f"confirm2_{cot.get('id', '')}_{i}")
                        
                        if st.form_submit_button("EXCLUIR COTAÇÃO", 
                                               disabled=not (confirmar1 and confirmar2),
                                               type="secondary"):
                            try:
                                if excluir_cotacao(cot.get('id', '')):
                                    st.success("Cotação excluída com sucesso!")
                                    adicionar_log_seguranca({
                                        'usuario_id': st.session_state.usuario_id,
                                        'acao': 'EXCLUIR_COTACAO',
                                        'descricao': f'Cotação ID: {cot.get("id", "")}',
                                        'ip': 'N/A',
                                        'user_agent': 'N/A',
                                        'created_at': datetime.now()
                                    })
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("Erro ao excluir cotação")
                            except Exception as e:
                                st.error(f"Erro ao excluir cotação: {str(e)}")
        else:
            st.info("Nenhuma cotação recebida ainda")
            
    except Exception as e:
        st.error(f"Erro no sistema: {str(e)}")
        st.info("Tente recarregar a página")

# =============================================
# TRANSPORTADORAS CADASTRADAS (SOLICITANTE)
# =============================================
elif menu == "Transportadoras Cadastradas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Transportadoras Cadastradas")
    
    try:
        usuarios = get_usuarios()
        transportadoras = [u for u in usuarios if u.get('tipo') == 'transportadora' and u.get('status') == 'Ativa']
        
        if transportadoras:
            st.info(f"**Total de transportadoras:** {len(transportadoras)}")
            
            for transp in transportadoras:
                with st.expander(f"{transp.get('razao_social', '')}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown(f"**Razão Social:** {transp.get('razao_social', '')}")
                        st.markdown(f"**CNPJ:** {transp.get('cnpj', '')}")
                        st.markdown(f"**E-mail:** {transp.get('email', '')}")
                    with col2:
                        st.markdown(f"**Telefone:** {transp.get('telefone', '')}")
                        st.markdown(f"**Cidade:** {transp.get('cidade', '')}")
                        st.markdown(f"**Data Cadastro:** {transp.get('data_cadastro', '')}")
        else:
            st.info("Nenhuma transportadora cadastrada")
    except Exception as e:
        st.error(f"Erro ao carregar transportadoras: {e}")

# =============================================
# FRETES DISPONÍVEIS (PARA TRANSPORTADORAS)
# =============================================
elif menu == "Fretes Disponíveis" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### Fretes Disponíveis para Cotação")
    
    try:
        solicitacoes = get_solicitacoes()
        solicitacoes_abertas = [s for s in solicitacoes if s.get('status') == 'Aberta']
        solicitacoes_abertas.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        if solicitacoes_abertas:
            st.info(f"**Total de fretes disponíveis:** {len(solicitacoes_abertas)}")
            
            for sol in solicitacoes_abertas:
                # Buscar cotações existentes
                cotacoes_existentes = get_cotacoes_por_solicitacao(sol.get('id'))
                cotacoes_existentes.sort(key=lambda x: float(x.get('valor_frete', 0)) if x.get('valor_frete') else 0)
                
                with st.expander(f"{sol.get('id', '')} - {sol.get('local_coleta', '')} → {sol.get('local_entrega', '')} - {len(cotacoes_existentes)} cotações"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Material:** {sol.get('material', '')}")
                        valor_carga = float(sol.get('valor_carga', 0)) if sol.get('valor_carga') else 0
                        st.markdown(f"**Valor da Carga:** R$ {valor_carga:,.2f}")
                        st.markdown(f"**Data Coleta:** {sol.get('data_coleta', '')}")
                        st.markdown(f"**Tomador:** {sol.get('tomador', '')}")
                    
                    with col2:
                        st.markdown(f"**Data Entrega:** {sol.get('data_entrega', '')}")
                        st.markdown(f"**Observações:** {sol.get('observacoes', '') if sol.get('observacoes') else 'Nenhuma'}")
                        st.markdown(f"**Publicada em:** {data_ptbr(sol.get('created_at', ''))}")
                    
                    # LEILÃO REVERSO - MOSTRAR COTAÇÕES EXISTENTES (SEM NOMES)
                    if cotacoes_existentes:
                        st.markdown("---")
                        st.markdown("#### Ranking Atual de Cotações")
                        
                        for i, cot in enumerate(cotacoes_existentes[:5]):
                            posicao = i + 1
                            emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                            
                            tempo = tempo_desde(cot.get('created_at', ''))
                            valor_frete = float(cot.get('valor_frete', 0)) if cot.get('valor_frete') else 0
                            
                            st.markdown(f"{emoji} **R$ {valor_frete:,.2f}** | {cot.get('prazo_entrega', '')} | {tempo}")
                        
                        if len(cotacoes_existentes) > 5:
                            st.info(f"... e mais {len(cotacoes_existentes) - 5} cotações")
                    
                    # FORMULÁRIO PARA ENVIAR COTAÇÃO
                    st.markdown("---")
                    with st.form(f"cotacao_form_{sol.get('id', '')}"):
                        st.markdown("#### Enviar Minha Cotação")
                        
                        col_valor, col_prazo = st.columns(2)
                        with col_valor:
                            valor_frete = st.number_input("Meu Valor (R$)", min_value=0.0, format="%.2f", key=f"valor_{sol.get('id', '')}")
                        with col_prazo:
                            prazo_entrega = st.selectbox("Meu Prazo", ["2 dias", "3 dias", "4 dias", "5 dias", "1 semana"], key=f"prazo_{sol.get('id', '')}")
                        
                        observacoes = st.text_area("Minhas Observações", placeholder="Condições especiais, observações...", key=f"obs_{sol.get('id', '')}")
                        
                        submitted = st.form_submit_button("Enviar Cotação")
                        
                        if submitted:
                            if valor_frete > 0:
                                # Verificar se já existe cotação desta transportadora para esta solicitação
                                todas_cotacoes = get_cotacoes()
                                ja_cotou = any(
                                    cot.get('solicitacao_id') == sol.get('id') and 
                                    cot.get('transportadora_id') == st.session_state.usuario_id 
                                    for cot in todas_cotacoes
                                )
                                
                                if ja_cotou:
                                    st.error("Você já enviou uma cotação para este frete!")
                                else:
                                    cotacao_id = f"COT-{uuid.uuid4().hex[:8].upper()}"
                                    cotacao_dict = {
                                        'id': cotacao_id,
                                        'solicitacao_id': sol.get('id', ''),
                                        'transportadora_id': st.session_state.usuario_id,
                                        'transportadora_nome': st.session_state.razao_social,
                                        'valor_frete': valor_frete,
                                        'prazo_entrega': prazo_entrega,
                                        'observacoes': observacoes,
                                        'status': 'Pendente',
                                        'created_at': datetime.now()
                                    }
                                    
                                    if adicionar_cotacao(cotacao_dict):
                                        st.success("Cotação enviada com sucesso! Agora outras empresas verão seu valor (sem seu nome)")
                                        adicionar_log_seguranca({
                                            'usuario_id': st.session_state.usuario_id,
                                            'acao': 'NOVA_COTACAO',
                                            'descricao': f'Cotação: {cotacao_id} para Solicitação: {sol.get("id", "")}',
                                            'ip': 'N/A',
                                            'user_agent': 'N/A',
                                            'created_at': datetime.now()
                                        })
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("Erro ao enviar cotação")
                            else:
                                st.error("Informe um valor válido para o frete")
        else:
            st.info("Nenhum frete disponível para cotação no momento")
    except Exception as e:
        st.error(f"Erro ao carregar fretes: {e}")

# =============================================
# MINHAS COTAÇÕES (TRANSPORTADORAS)
# =============================================
elif menu == "Minhas Cotações" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### Minhas Cotações Enviadas")
    
    try:
        minhas_cotacoes = get_cotacoes_por_transportadora(st.session_state.usuario_id)
        minhas_cotacoes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        if minhas_cotacoes:
            # Estatísticas
            total_cotacoes = len(minhas_cotacoes)
            cotacoes_aceitas = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Aceita")
            cotacoes_pendentes = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Pendente")
            cotacoes_recusadas = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Recusada")
            
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total", total_cotacoes)
            with col2:
                st.metric("Pendentes", cotacoes_pendentes)
            with col3:
                st.metric("Aceitas", cotacoes_aceitas)
            with col4:
                st.metric("Recusadas", cotacoes_recusadas)
            
            st.markdown("---")
            
            for cot in minhas_cotacoes:
                # Obter informações da solicitação
                solicitacao = get_solicitacao_por_id(cot.get('solicitacao_id', ''))
                
                if solicitacao:
                    # Definir cores e emojis baseados no status
                    if cot.get('status') == "Aceita":
                        status_color = "✅"
                        status_text = "Cotação Aceita"
                        border_color = "2px solid #10b981"
                    elif cot.get('status') == "Recusada":
                        status_color = "❌"
                        status_text = "Cotação Recusada"
                        border_color = "2px solid #ef4444"
                    else:
                        status_color = "⏳"
                        status_text = "Aguardando Avaliação"
                        border_color = "2px solid #f59e0b"
                    
                    valor_frete = float(cot.get('valor_frete', 0)) if cot.get('valor_frete') else 0
                    
                    with st.expander(f"{status_color} {cot.get('id', '')} - {solicitacao.get('local_coleta', '')} → {solicitacao.get('local_entrega', '')} - R$ {valor_frete:,.2f}"):
                        # Card com borda colorida baseada no status
                        st.markdown(f"""
                        <div style="border-left: {border_color}; padding-left: 1rem; margin-bottom: 1rem;">
                            <h4>{status_text}</h4>
                        </div>
                        """, unsafe_allow_html=True)
                        
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.markdown(f"**Material:** {solicitacao.get('material', '')}")
                            st.markdown(f"**Meu Valor:** R$ {valor_frete:,.2f}")
                            st.markdown(f"**Meu Prazo:** {cot.get('prazo_entrega', '')}")
                            st.markdown(f"**Local Coleta:** {solicitacao.get('local_coleta', '')}")
                            st.markdown(f"**Local Entrega:** {solicitacao.get('local_entrega', '')}")
                        
                        with col2:
                            st.markdown(f"**Solicitação:** {cot.get('solicitacao_id', '')}")
                            st.markdown(f"**Data Envio:** {data_ptbr(cot.get('created_at', ''))}")
                            st.markdown(f"**Status Solicitação:** {solicitacao.get('status', '')}")
                            st.markdown(f"**Minhas Observações:** {cot.get('observacoes', '') if cot.get('observacoes') else 'Nenhuma'}")
                            
                            # Botão para cancelar cotação se ainda estiver pendente
                            if cot.get('status') == "Pendente":
                                st.markdown("---")
                                if st.button("Cancelar Cotação", key=f"cancelar_{cot.get('id', '')}"):
                                    if excluir_cotacao(cot.get('id', '')):
                                        st.success("Cotação cancelada com sucesso!")
                                        adicionar_log_seguranca({
                                            'usuario_id': st.session_state.usuario_id,
                                            'acao': 'CANCELAR_COTACAO',
                                            'descricao': f'Cotação ID: {cot.get("id", "")}',
                                            'ip': 'N/A',
                                            'user_agent': 'N/A',
                                            'created_at': datetime.now()
                                        })
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("Erro ao cancelar cotação")
        else:
            st.info("Você ainda não enviou nenhuma cotação")
    except Exception as e:
        st.error(f"Erro ao carregar cotações: {e}")

# =============================================
# BACKUP DE DADOS (APENAS SOLICITANTE)
# =============================================
elif menu == "Backup de Dados" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Backup de Dados")
    
    st.info("""
    **Gerar backup completo** de todas as suas solicitações e cotações em formato Excel.
    O arquivo será baixado automaticamente para seu computador.
    """)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        st.markdown("#### Dados Incluídos no Backup:")
        st.markdown("✅ Todas as suas solicitações")
        st.markdown("✅ Todas as cotações recebidas") 
        st.markdown("✅ Informações completas de cada registro")
        st.markdown("✅ Data e hora de criação")
        st.markdown("✅ Status atualizados")
    
    with col2:
        st.markdown("#### Informações:")
        st.markdown("**Formato:** Excel (.xlsx)")
        st.markdown("**Codificação:** UTF-8")
        st.markdown("**Atualizado em:** tempo real")
    
    st.markdown("---")
    
    # Botão para gerar backup
    if st.button("GERAR BACKUP COMPLETO", type="primary", use_container_width=True):
        with st.spinner("Gerando arquivo de backup..."):
            try:
                # Obter dados do banco
                solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
                todas_cotacoes = get_cotacoes()
                usuarios = get_usuarios()
                
                dados_excel = []
                
                # Adicionar solicitações
                for sol in solicitacoes:
                    usuario_nome = "N/A"
                    for usuario in usuarios:
                        if usuario.get('id') == sol.get('usuario_id'):
                            usuario_nome = usuario.get('razao_social')
                            break
                    
                    dados_excel.append({
                        'Tipo': 'SOLICITAÇÃO',
                        'ID': sol.get('id', ''),
                        'Local Coleta': sol.get('local_coleta', ''),
                        'Local Entrega': sol.get('local_entrega', ''),
                        'Material': sol.get('material', ''),
                        'Valor Carga': f"R$ {float(sol.get('valor_carga', 0)):,.2f}" if sol.get('valor_carga') else '',
                        'Data Coleta': sol.get('data_coleta', ''),
                        'Data Entrega': sol.get('data_entrega', ''),
                        'Tomador': sol.get('tomador', ''),
                        'Observações': sol.get('observacoes', '') or '',
                        'Status': sol.get('status', ''),
                        'Criado em': data_ptbr(sol.get('created_at', '')),
                        'Usuário': usuario_nome
                    })
                
                # Adicionar cotações
                for cot in todas_cotacoes:
                    # Verificar se a cotação é para uma solicitação do usuário
                    solicitacao = get_solicitacao_por_id(cot.get('solicitacao_id'))
                    if solicitacao and solicitacao.get('usuario_id') == st.session_state.usuario_id:
                        # Encontrar nome da transportadora
                        transportadora_nome = cot.get('transportadora_nome', '')
                        for usuario in usuarios:
                            if usuario.get('id') == cot.get('transportadora_id'):
                                transportadora_nome = usuario.get('razao_social')
                                break
                        
                        dados_excel.append({
                            'Tipo': 'COTAÇÃO',
                            'ID': cot.get('id', ''),
                            'Solicitação ID': cot.get('solicitacao_id', ''),
                            'Transportadora': transportadora_nome,
                            'Valor Frete': f"R$ {float(cot.get('valor_frete', 0)):,.2f}" if cot.get('valor_frete') else '',
                            'Prazo Entrega': cot.get('prazo_entrega', ''),
                            'Observações': cot.get('observacoes', '') or '',
                            'Status': cot.get('status', ''),
                            'Criado em': data_ptbr(cot.get('created_at', '')),
                            'Local Coleta': solicitacao.get('local_coleta', ''),
                            'Local Entrega': solicitacao.get('local_entrega', '')
                        })
                
                df = pd.DataFrame(dados_excel)
                data_atual = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
                filename = f"backup_solicitacoes_{data_atual}.xlsx"
                
                # Salvar arquivo
                df.to_excel(filename, index=False, engine='openpyxl')
                
                st.success(f"Backup gerado com sucesso!")
                st.info(f"**Arquivo:** {filename}")
                st.info(f"**Registros exportados:** {len(df)}")
                
                # Mostrar prévia dos dados
                st.markdown("#### Prévia dos Dados Exportados:")
                st.dataframe(df.head(10), use_container_width=True)
                
                # Botão para download
                with open(filename, "rb") as file:
                    btn = st.download_button(
                        label="BAIXAR ARQUIVO EXCEL",
                        data=file,
                        file_name=filename,
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="primary",
                        use_container_width=True
                    )
                
                if btn:
                    st.balloons()
                    st.success("Download iniciado! Verifique sua pasta de downloads.")
                    adicionar_log_seguranca({
                        'usuario_id': st.session_state.usuario_id,
                        'acao': 'BACKUP_GERADO',
                        'descricao': f'Arquivo: {filename}',
                        'ip': 'N/A',
                        'user_agent': 'N/A',
                        'created_at': datetime.now()
                    })
                        
            except Exception as e:
                st.error(f"Erro ao gerar backup: {str(e)}")
    
    # Estatísticas rápidas
    st.markdown("---")
    st.markdown("### Estatísticas do Backup")
    
    try:
        solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        
        total_solicitacoes = len(solicitacoes)
        
        # Contar cotações das minhas solicitações
        total_cotacoes = 0
        for sol in solicitacoes:
            cotacoes_sol = get_cotacoes_por_solicitacao(sol.get('id', ''))
            total_cotacoes += len(cotacoes_sol)
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Solicitações para Exportar", total_solicitacoes)
        with col2:
            st.metric("Cotações para Exportar", total_cotacoes)
            
    except Exception as e:
        st.error(f"Erro ao carregar estatísticas: {str(e)}")

# =============================================
# MEU PERFIL
# =============================================
elif menu == "Meu Perfil":
    st.markdown("### Meu Perfil")
    
    usuario = get_usuario_por_id(st.session_state.usuario_id)
    
    if usuario:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Razão Social:** {usuario.get('razao_social', '')}")
            st.markdown(f"**CNPJ:** {usuario.get('cnpj', '')}")
            st.markdown(f"**E-mail:** {usuario.get('email', '')}")
        with col2:
            st.markdown(f"**Telefone:** {usuario.get('telefone', '')}")
            st.markdown(f"**Cidade:** {usuario.get('cidade', '')}")
            st.markdown(f"**Tipo:** {'Solicitante' if usuario.get('tipo') == 'solicitante' else 'Transportadora'}")
            st.markdown(f"**Data Cadastro:** {usuario.get('data_cadastro', '')}")
        
        st.markdown("---")
        st.markdown("### Alterar Senha")
        with st.form("alterar_senha"):
            senha_atual = st.text_input("Senha Atual", type="password")
            nova_senha = st.text_input("Nova Senha", type="password")
            confirmar_senha = st.text_input("Confirmar Nova Senha", type="password")
            
            if st.form_submit_button("Atualizar Senha"):
                if senha_atual and nova_senha and confirmar_senha:
                    if hash_senha(senha_atual) == usuario.get('senha_hash', ''):
                        if nova_senha == confirmar_senha:
                            senha_valida, msg_senha = validar_senha_forte(nova_senha)
                            if not senha_valida:
                                st.error(msg_senha)
                            else:
                                if atualizar_usuario(st.session_state.usuario_id, {'senha_hash': hash_senha(nova_senha)}):
                                    st.success("Senha atualizada com sucesso!")
                                    adicionar_log_seguranca({
                                        'usuario_id': st.session_state.usuario_id,
                                        'acao': 'SENHA_ALTERADA',
                                        'descricao': 'Senha do usuário alterada',
                                        'ip': 'N/A',
                                        'user_agent': 'N/A',
                                        'created_at': datetime.now()
                                    })
                                else:
                                    st.error("Erro ao atualizar senha")
                        else:
                            st.error("As novas senhas não coincidem")
                    else:
                        st.error("Senha atual incorreta")
                else:
                    st.error("Preencha todos os campos")

# FOOTER
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #718096; padding: 2rem;'>
    <strong>🌐Sistema de Cotações C3 Engenharia © 2025</strong><br>
    <small>🔒Sistema protegido com medidas de segurança avançadas</small>
</div>
""", unsafe_allow_html=True)

