import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import uuid
import hashlib
import secrets
import re
import string
import os
import sqlite3
from sqlalchemy import create_engine, Column, String, Integer, Float, DateTime, Text, Boolean, func, and_, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session
from sqlalchemy.exc import IntegrityError
import bcrypt
import time
import plotly.express as px
import plotly.graph_objects as go

# =============================================
# CONFIGURAÇÕES DE SEGURANÇA
# =============================================
MAX_TENTATIVAS_LOGIN = 5
BLOQUEIO_MINUTOS = 15
PEPPER = os.environ.get('PEPPER', 'c3_secret_pepper_2025')

# =============================================
# FUNÇÕES DE HASH SEGURO
# =============================================
def hash_senha(senha):
    senha_com_pepper = senha + PEPPER
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(senha_com_pepper.encode('utf-8'), salt).decode('utf-8')

def verificar_senha(senha, hash_armazenado):
    senha_com_pepper = senha + PEPPER
    return bcrypt.checkpw(senha_com_pepper.encode('utf-8'), hash_armazenado.encode('utf-8'))

def criptografar_dado(dado):
    if not dado:
        return None
    salt = secrets.token_hex(16)
    hash_obj = hashlib.pbkdf2_hmac('sha256', dado.encode(), salt.encode(), 100000)
    return f"{salt}:{hash_obj.hex()}"

def verificar_dado_criptografado(dado, hash_armazenado):
    if not hash_armazenado:
        return False
    try:
        salt, hash_dado = hash_armazenado.split(':')
        hash_verificar = hashlib.pbkdf2_hmac('sha256', dado.encode(), salt.encode(), 100000)
        return secrets.compare_digest(hash_verificar.hex(), hash_dado)
    except:
        return False

# =============================================
# MODELOS DE DADOS
# =============================================
Base = declarative_base()

class Usuario(Base):
    __tablename__ = 'usuarios'
    id = Column(String, primary_key=True)
    razao_social = Column(String(200), nullable=False, unique=True)
    cnpj_hash = Column(String(255), nullable=False)
    cnpj_ultimos4 = Column(String(4))
    email_hash = Column(String(255), nullable=False)
    telefone = Column(String(20))
    cidade = Column(String(100))
    senha_hash = Column(String(255), nullable=False)
    tipo = Column(String(20), default='transportadora')
    status = Column(String(20), default='Ativa')
    data_cadastro = Column(DateTime, default=datetime.now)
    ultimo_login = Column(DateTime)
    tentativas_login = Column(Integer, default=0)
    bloqueado_ate = Column(DateTime)

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
    leilao_encerrado = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.now)
    vencedor_id = Column(String)
    valor_vencedor = Column(Float)

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
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)

class LogSeguranca(Base):
    __tablename__ = 'logs_seguranca'
    id = Column(Integer, primary_key=True, autoincrement=True)
    usuario_id = Column(String)
    acao = Column(String(100))
    descricao = Column(Text)
    ip = Column(String(50))
    user_agent = Column(String(200))
    created_at = Column(DateTime, default=datetime.now)

class TentativaLogin(Base):
    __tablename__ = 'tentativas_login'
    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(50))
    tentativas = Column(Integer, default=0)
    bloqueado_ate = Column(DateTime)
    created_at = Column(DateTime, default=datetime.now)

# =============================================
# CONFIGURAÇÃO DO BANCO
# =============================================
engine = create_engine('sqlite:///c3_engenharia.db', connect_args={'check_same_thread': False})
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(bind=engine))

def get_session():
    return Session()

# =============================================
# FUNÇÕES DE BANCO DE DADOS - COMPLETAS
# =============================================

def get_usuarios():
    session = get_session()
    try:
        usuarios = session.query(Usuario).all()
        return [{
            'id': u.id,
            'razao_social': u.razao_social,
            'cnpj_ultimos4': u.cnpj_ultimos4,
            'email': '****@****',  # Não expor email completo
            'telefone': u.telefone,
            'cidade': u.cidade,
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
                'telefone': usuario.telefone,
                'cidade': usuario.cidade,
                'tipo': usuario.tipo,
                'status': usuario.status,
                'data_cadastro': usuario.data_cadastro.strftime('%d-%m-%Y %H:%M:%S') if usuario.data_cadastro else None
            }
        return None
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
            'leilao_encerrado': s.leilao_encerrado,
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
            'leilao_encerrado': s.leilao_encerrado,
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
                'leilao_encerrado': solicitacao.leilao_encerrado,
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
        session.query(Cotacao).filter_by(solicitacao_id=solicitacao_id).delete()
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
            'created_at': c.created_at.strftime('%d-%m-%Y %H:%M:%S') if c.created_at else None,
            'updated_at': c.updated_at.strftime('%d-%m-%Y %H:%M:%S') if c.updated_at else None
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
            'created_at': c.created_at.strftime('%d-%m-%Y %H:%M:%S') if c.created_at else None,
            'updated_at': c.updated_at.strftime('%d-%m-%Y %H:%M:%S') if c.updated_at else None
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
            'created_at': c.created_at.strftime('%d-%m-%Y %H:%M:%S') if c.created_at else None,
            'updated_at': c.updated_at.strftime('%d-%m-%Y %H:%M:%S') if c.updated_at else None
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
                'created_at': cotacao.created_at.strftime('%d-%m-%Y %H:%M:%S') if cotacao.created_at else None,
                'updated_at': cotacao.updated_at.strftime('%d-%m-%Y %H:%M:%S') if cotacao.updated_at else None
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
            cotacao.updated_at = datetime.now()
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

def adicionar_log_seguranca(usuario_id, acao, descricao, ip=None, user_agent=None):
    session = get_session()
    try:
        log = LogSeguranca(
            usuario_id=usuario_id,
            acao=acao,
            descricao=descricao,
            ip=ip or 'N/A',
            user_agent=user_agent or 'N/A',
            created_at=datetime.now()
        )
        session.add(log)
        session.commit()
        return True
    except Exception as e:
        session.rollback()
        return False
    finally:
        session.close()

# =============================================
# FUNÇÕES DE VALIDAÇÃO
# =============================================

def validar_cnpj(cnpj):
    cnpj = re.sub(r'[^0-9]', '', str(cnpj))
    return len(cnpj) == 14

def validar_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validar_telefone(telefone):
    telefone = re.sub(r'[^0-9]', '', str(telefone))
    return len(telefone) >= 10 and len(telefone) <= 11

def validar_senha_forte(senha):
    if len(senha) < 10:
        return False, "Mínimo 10 caracteres"
    if not any(c.isupper() for c in senha):
        return False, "Pelo menos 1 letra maiúscula"
    if not any(c.islower() for c in senha):
        return False, "Pelo menos 1 letra minúscula"
    if not any(c.isdigit() for c in senha):
        return False, "Pelo menos 1 número"
    if not any(c in "!@#$%&*" for c in senha):
        return False, "Pelo menos 1 caractere especial (!@#$%&*)"
    return True, "OK"

# =============================================
# FUNÇÕES DE ESTATÍSTICAS
# =============================================

def get_estatisticas_solicitante(usuario_id):
    solicitacoes = get_solicitacoes_por_usuario(usuario_id)
    usuarios = get_usuarios()
    cotacoes = get_cotacoes()
    
    solicitacoes_ativas = sum(1 for s in solicitacoes if s.get('status') == 'Aberta' and not s.get('leilao_encerrado'))
    total_transportadoras = sum(1 for u in usuarios if u.get('tipo') == 'transportadora' and u.get('status') == 'Ativa')
    
    total_cotacoes = 0
    for sol in solicitacoes:
        cotacoes_solicitacao = get_cotacoes_por_solicitacao(sol['id'])
        total_cotacoes += len(cotacoes_solicitacao)
    
    return {
        'solicitacoes_ativas': solicitacoes_ativas,
        'total_transportadoras': total_transportadoras,
        'total_cotacoes': total_cotacoes
    }

def get_estatisticas_transportadora(transportadora_id):
    cotacoes = get_cotacoes_por_transportadora(transportadora_id)
    
    total_cotacoes = len(cotacoes)
    cotacoes_aceitas = sum(1 for cot in cotacoes if cot.get('status') == 'Aceita')
    cotacoes_pendentes = sum(1 for cot in cotacoes if cot.get('status') == 'Pendente')
    
    return {
        'total_cotacoes': total_cotacoes,
        'cotacoes_aceitas': cotacoes_aceitas,
        'cotacoes_pendentes': cotacoes_pendentes
    }

# =============================================
# FUNÇÕES DE LOGIN COM RATE LIMIT
# =============================================

def verificar_rate_limit(ip):
    session = get_session()
    try:
        tentativa = session.query(TentativaLogin).filter_by(ip=ip).first()
        
        if tentativa and tentativa.bloqueado_ate and tentativa.bloqueado_ate > datetime.now():
            return False, f"Muitas tentativas. Tente novamente após {tentativa.bloqueado_ate.strftime('%H:%M')}"
        
        return True, "OK"
    finally:
        session.close()

def registrar_tentativa_falha(ip):
    session = get_session()
    try:
        tentativa = session.query(TentativaLogin).filter_by(ip=ip).first()
        
        if tentativa:
            tentativa.tentativas += 1
            if tentativa.tentativas >= MAX_TENTATIVAS_LOGIN:
                tentativa.bloqueado_ate = datetime.now() + timedelta(minutes=BLOQUEIO_MINUTOS)
        else:
            tentativa = TentativaLogin(ip=ip, tentativas=1)
            session.add(tentativa)
        
        session.commit()
    finally:
        session.close()

def resetar_tentativas(ip):
    session = get_session()
    try:
        tentativa = session.query(TentativaLogin).filter_by(ip=ip).first()
        if tentativa:
            session.delete(tentativa)
            session.commit()
    finally:
        session.close()

def verificar_login(razao_social, senha, ip):
    rate_ok, msg = verificar_rate_limit(ip)
    if not rate_ok:
        return None, msg
    
    session = get_session()
    try:
        usuario = session.query(Usuario).filter(
            func.lower(Usuario.razao_social) == func.lower(razao_social)
        ).first()
        
        if not usuario:
            registrar_tentativa_falha(ip)
            return None, "Razão Social ou senha incorretos"
        
        if usuario.bloqueado_ate and usuario.bloqueado_ate > datetime.now():
            return None, f"Usuário bloqueado até {usuario.bloqueado_ate.strftime('%H:%M')}"
        
        if not verificar_senha(senha, usuario.senha_hash):
            usuario.tentativas_login += 1
            if usuario.tentativas_login >= MAX_TENTATIVAS_LOGIN:
                usuario.bloqueado_ate = datetime.now() + timedelta(minutes=BLOQUEIO_MINUTOS)
            session.commit()
            registrar_tentativa_falha(ip)
            return None, "Razão Social ou senha incorretos"
        
        usuario.tentativas_login = 0
        usuario.ultimo_login = datetime.now()
        session.commit()
        resetar_tentativas(ip)
        
        adicionar_log_seguranca(usuario.id, 'LOGIN_SUCESSO', 'Login realizado com sucesso', ip)
        
        return {
            'id': usuario.id,
            'razao_social': usuario.razao_social,
            'tipo': usuario.tipo,
            'status': usuario.status
        }, None
        
    finally:
        session.close()

def cadastrar_usuario(razao_social, cnpj, email, telefone, cidade, senha, tipo='transportadora', ip=None):
    if razao_social.lower() == "c3 engenharia":
        return False, "Esta razão social é reservada"
    
    if not validar_senha_forte(senha)[0]:
        return False, "Senha não atende aos requisitos mínimos"
    
    if not validar_cnpj(cnpj):
        return False, "CNPJ inválido"
    
    if not validar_email(email):
        return False, "E-mail inválido"
    
    if not validar_telefone(telefone):
        return False, "Telefone inválido"
    
    session = get_session()
    try:
        if session.query(Usuario).filter(func.lower(Usuario.razao_social) == func.lower(razao_social)).first():
            return False, "Razão Social já cadastrada"
        
        usuario_id = f"USER-{secrets.token_hex(8).upper()}"
        cnpj_limpo = re.sub(r'[^0-9]', '', cnpj)
        cnpj_hash = criptografar_dado(cnpj_limpo)
        email_hash = criptografar_dado(email.lower())
        
        novo_usuario = Usuario(
            id=usuario_id,
            razao_social=razao_social,
            cnpj_hash=cnpj_hash,
            cnpj_ultimos4=cnpj_limpo[-4:] if len(cnpj_limpo) >= 4 else cnpj_limpo,
            email_hash=email_hash,
            telefone=telefone,
            cidade=cidade,
            senha_hash=hash_senha(senha),
            tipo=tipo,
            status='Ativa',
            data_cadastro=datetime.now()
        )
        
        session.add(novo_usuario)
        session.commit()
        
        adicionar_log_seguranca(usuario_id, 'CADASTRO', f'Novo usuário: {razao_social}', ip)
        return True, "Cadastro realizado com sucesso!"
        
    except IntegrityError:
        session.rollback()
        return False, "Dados já cadastrados"
    finally:
        session.close()

# =============================================
# FUNÇÕES DE DATA
# =============================================

def data_ptbr(data_str):
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
    except:
        return str(data_str)

def tempo_desde(data_str):
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
# INICIALIZAÇÃO DO SISTEMA (ADMIN SEGURO)
# =============================================

def inicializar_sistema():
    session = get_session()
    try:
        admin = session.query(Usuario).filter(
            func.lower(Usuario.razao_social) == "c3 engenharia"
        ).first()
        
        if not admin:
            senha_admin = secrets.token_urlsafe(12)
            cnpj_limpo = "12345678000190"
            
            admin_id = "ADMIN-001"
            admin = Usuario(
                id=admin_id,
                razao_social="C3 Engenharia",
                cnpj_hash=criptografar_dado(cnpj_limpo),
                cnpj_ultimos4=cnpj_limpo[-4:],
                email_hash=criptografar_dado("admin@c3engenharia.com.br"),
                telefone="(19) 99999-9999",
                cidade="Santa Bárbara D'Oeste - SP",
                senha_hash=hash_senha(senha_admin),
                tipo="solicitante",
                status="Ativa",
                data_cadastro=datetime.now()
            )
            
            session.add(admin)
            session.commit()
            
            with open('admin_credentials.txt', 'w') as f:
                f.write("="*50 + "\n")
                f.write("CREDENCIAIS DE ACESSO ADMIN\n")
                f.write("="*50 + "\n\n")
                f.write(f"Usuário: C3 Engenharia\n")
                f.write(f"Senha: {senha_admin}\n\n")
                f.write("IMPORTANTE: Altere a senha no primeiro acesso!\n")
                f.write("="*50 + "\n")
            
            print(f"✅ Admin criado. Credenciais salvas em admin_credentials.txt")
    except Exception as e:
        print(f"⚠️ Erro na inicialização: {e}")
    finally:
        session.close()

# =============================================
# CONFIGURAÇÃO DO STREAMLIT
# =============================================
st.set_page_config(
    page_title="C3 Freights - Sistema de Leilão de Fretes",
    page_icon="🏆",
    layout="wide",
    initial_sidebar_state="expanded"
)

# CSS COMPLETO (mantido do código anterior)
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
    
    * { font-family: 'Inter', sans-serif; margin: 0; padding: 0; box-sizing: border-box; }
    
    @media (prefers-color-scheme: dark) {
        :root {
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border-color: #334155;
            --card-bg: #1e293b;
            --hover-bg: #334155;
        }
    }
    
    @media (prefers-color-scheme: light) {
        :root {
            --bg-primary: #f8fafc;
            --bg-secondary: #ffffff;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --border-color: #e2e8f0;
            --card-bg: #ffffff;
            --hover-bg: #f1f5f9;
        }
    }
    
    @keyframes fadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to { opacity: 1; transform: translateY(0); }
    }
    
    @keyframes slideIn {
        from { transform: translateX(-100%); }
        to { transform: translateX(0); }
    }
    
    .main-header {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 2rem;
        border-radius: 1rem;
        margin-bottom: 2rem;
        animation: fadeIn 0.5s ease;
    }
    
    .main-header h1 { color: white; font-size: 2rem; font-weight: 700; margin: 0; }
    .main-header p { color: rgba(255,255,255,0.9); margin-top: 0.5rem; }
    
    .metric-card {
        background: var(--card-bg);
        border-radius: 1rem;
        padding: 1.5rem;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
        transition: all 0.3s ease;
        border: 1px solid var(--border-color);
        animation: fadeIn 0.5s ease;
        text-align: center;
    }
    
    .metric-card:hover { transform: translateY(-4px); box-shadow: 0 20px 25px -5px rgba(0,0,0,0.1); }
    .metric-value { font-size: 2.5rem; font-weight: 800; color: #667eea; margin: 0.5rem 0; }
    .metric-label { color: var(--text-secondary); font-size: 0.875rem; font-weight: 500; text-transform: uppercase; }
    
    .frete-card {
        background: var(--card-bg);
        border-radius: 1rem;
        padding: 1.5rem;
        margin-bottom: 1rem;
        border: 1px solid var(--border-color);
        transition: all 0.3s ease;
        animation: fadeIn 0.5s ease;
    }
    
    .frete-card:hover { box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); transform: translateX(4px); }
    
    .badge-success { background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-warning { background: linear-gradient(135deg, #f59e0b, #d97706); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-danger { background: linear-gradient(135deg, #ef4444, #dc2626); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    .badge-info { background: linear-gradient(135deg, #3b82f6, #2563eb); color: white; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.75rem; font-weight: 600; }
    
    .stButton button { transition: all 0.3s ease; border-radius: 0.5rem; font-weight: 600; }
    .stButton button:hover { transform: translateY(-2px); box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    
    .user-avatar {
        width: 48px;
        height: 48px;
        background: linear-gradient(135deg, #667eea, #764ba2);
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        color: white;
        font-weight: 700;
        font-size: 1.25rem;
        transition: all 0.3s ease;
    }
    
    .user-avatar:hover { transform: scale(1.1); }
    
    .toast-notification {
        position: fixed;
        top: 20px;
        right: 20px;
        background: var(--card-bg);
        border-left: 4px solid;
        border-radius: 0.5rem;
        padding: 1rem;
        box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1);
        z-index: 1000;
        animation: slideIn 0.3s ease;
        max-width: 400px;
    }
    
    .toast-success { border-left-color: #10b981; }
    .toast-error { border-left-color: #ef4444; }
    .toast-warning { border-left-color: #f59e0b; }
    .toast-info { border-left-color: #3b82f6; }
</style>
""", unsafe_allow_html=True)

# =============================================
# FUNÇÕES DE NOTIFICAÇÃO
# =============================================

def show_toast(message, type='success'):
    st.markdown(f"""
    <div class="toast-notification toast-{type}">
        <strong>{'✓' if type == 'success' else '⚠' if type == 'warning' else '✗' if type == 'error' else 'ℹ'}</strong>
        {message}
    </div>
    <script>
        setTimeout(() => {{
            const toast = document.querySelector('.toast-notification');
            if(toast) toast.remove();
        }}, 3000);
    </script>
    """, unsafe_allow_html=True)

# =============================================
# INICIALIZAÇÃO
# =============================================
inicializar_sistema()

# =============================================
# SISTEMA DE LOGIN
# =============================================
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    col1, col2, col3 = st.columns([1, 2, 1])
    
    with col2:
        st.markdown("""
        <div class="main-header" style="text-align: center;">
            <h1>🏆 C3 FREIGHTS</h1>
            <p>Sistema de Leilão de Fretes</p>
        </div>
        """, unsafe_allow_html=True)
        
        tab1, tab2 = st.tabs(["🔐 Login", "📝 Cadastro"])
        
        with tab1:
            with st.form("login_form"):
                razao_social = st.text_input("Razão Social", placeholder="Digite sua razão social")
                senha = st.text_input("Senha", type="password", placeholder="Digite sua senha")
                
                submitted = st.form_submit_button("Entrar no Sistema", use_container_width=True)
                
                if submitted:
                    if not razao_social or not senha:
                        show_toast("Preencha todos os campos", "error")
                    else:
                        ip = st.session_state.get('ip', '127.0.0.1')
                        
                        with st.spinner("Verificando credenciais..."):
                            usuario, erro = verificar_login(razao_social, senha, ip)
                            
                            if usuario:
                                st.session_state.logged_in = True
                                st.session_state.usuario_id = usuario['id']
                                st.session_state.razao_social = usuario['razao_social']
                                st.session_state.tipo_usuario = usuario['tipo']
                                
                                show_toast(f"Bem-vindo, {usuario['razao_social']}!", "success")
                                time.sleep(1)
                                st.rerun()
                            else:
                                show_toast(erro or "Credenciais inválidas", "error")
        
        with tab2:
            with st.form("cadastro_form"):
                razao_social = st.text_input("Razão Social*", max_chars=100)
                cnpj = st.text_input("CNPJ*", placeholder="00.000.000/0000-00", max_chars=18)
                email = st.text_input("E-mail*", max_chars=100)
                telefone = st.text_input("Telefone*", placeholder="(11) 99999-9999", max_chars=15)
                cidade = st.text_input("Cidade/UF*", max_chars=50)
                senha = st.text_input("Senha*", type="password")
                confirmar = st.text_input("Confirmar Senha*", type="password")
                
                st.caption("🔒 Requisitos: mínimo 10 caracteres, 1 maiúscula, 1 minúscula, 1 número, 1 caractere especial (!@#$%&*)")
                
                if st.form_submit_button("Cadastrar", use_container_width=True):
                    if not all([razao_social, cnpj, email, telefone, cidade, senha]):
                        show_toast("Preencha todos os campos", "error")
                    elif senha != confirmar:
                        show_toast("As senhas não coincidem", "error")
                    else:
                        with st.spinner("Cadastrando..."):
                            sucesso, msg = cadastrar_usuario(
                                razao_social, cnpj, email, telefone, cidade, senha,
                                tipo='transportadora', ip=st.session_state.get('ip', '127.0.0.1')
                            )
                            
                            if sucesso:
                                show_toast(msg, "success")
                                time.sleep(1)
                                st.rerun()
                            else:
                                show_toast(msg, "error")
    
    st.stop()

# =============================================
# SISTEMA PRINCIPAL
# =============================================

# Header
col1, col2, col3 = st.columns([2, 1, 1])
with col1:
    st.markdown(f"""
    <div class="main-header">
        <h1>🏆 C3 FREIGHTS</h1>
        <p>Sistema de Leilão de Fretes - {st.session_state.razao_social}</p>
    </div>
    """, unsafe_allow_html=True)

with col3:
    st.markdown(f"""
    <div style="display: flex; justify-content: flex-end; align-items: center; gap: 1rem;">
        <div class="user-avatar">
            {st.session_state.razao_social[:2].upper()}
        </div>
        <div>
            <strong>{st.session_state.razao_social[:30]}</strong><br>
            <small style="color: var(--text-secondary);">{'Solicitante' if st.session_state.tipo_usuario == 'solicitante' else 'Transportadora'}</small>
        </div>
    </div>
    """, unsafe_allow_html=True)
    
    if st.button("🚪 Sair", use_container_width=True):
        adicionar_log_seguranca(
            st.session_state.usuario_id,
            'LOGOUT',
            'Usuário desconectado',
            st.session_state.get('ip', 'N/A')
        )
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# Menu
st.sidebar.markdown("### 📋 Navegação")

if st.session_state.tipo_usuario == 'solicitante':
    menu_options = [
        "📊 Dashboard",
        "➕ Nova Solicitação",
        "📋 Gerenciar Solicitações",
        "💰 Cotações Recebidas",
        "🏆 Encerrar Leilão",
        "🚛 Transportadoras Cadastradas",
        "📁 Backup de Dados",
        "⚙️ Meu Perfil"
    ]
else:
    menu_options = [
        "📊 Dashboard",
        "🚚 Fretes Disponíveis",
        "📝 Minhas Cotações",
        "⚙️ Meu Perfil"
    ]

menu = st.sidebar.selectbox("Menu", menu_options, label_visibility="collapsed")

# Sidebar info
st.sidebar.markdown("---")
st.sidebar.markdown("### 🔒 Dicas de Segurança")
st.sidebar.info("""
• Nunca compartilhe sua senha
• Troque sua senha periodicamente
• Sempre faça logout ao sair
• Não acesse em computadores públicos
""")

st.sidebar.markdown("---")
st.sidebar.caption(f"🔐 Sessão segura | {datetime.now().strftime('%d/%m/%Y %H:%M')}")

# =============================================
# DASHBOARD
# =============================================
if menu == "📊 Dashboard":
    st.markdown("### 📊 Dashboard")
    
    if st.session_state.tipo_usuario == 'solicitante':
        with st.spinner("Carregando dados..."):
            stats = get_estatisticas_solicitante(st.session_state.usuario_id)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Solicitações Ativas</div>
                <div class="metric-value">{stats['solicitacoes_ativas']}</div>
                <small>Aguardando cotações</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Transportadoras</div>
                <div class="metric-value">{stats['total_transportadoras']}</div>
                <small>Ativas no sistema</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Cotações Recebidas</div>
                <div class="metric-value">{stats['total_cotacoes']}</div>
                <small>Total recebidas</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Atividade recente
        st.markdown("### 📈 Atividade Recente")
        solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        
        if solicitacoes:
            for sol in solicitacoes[:5]:
                cotacoes = get_cotacoes_por_solicitacao(sol['id'])
                with st.expander(f"{sol['id']} - {sol['local_coleta']} → {sol['local_entrega']}"):
                    st.write(f"**Material:** {sol['material']}")
                    st.write(f"**Status:** {sol['status']}")
                    st.write(f"**Cotações:** {len(cotacoes)}")
                    st.write(f"**Criada em:** {data_ptbr(sol['created_at'])}")
        else:
            st.info("Nenhuma solicitação criada ainda")
    
    else:
        # Dashboard Transportadora
        stats = get_estatisticas_transportadora(st.session_state.usuario_id)
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Cotações Enviadas</div>
                <div class="metric-value">{stats['total_cotacoes']}</div>
                <small>Total de participações</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Cotações Aceitas</div>
                <div class="metric-value">{stats['cotacoes_aceitas']}</div>
                <small>Fretes ganhos</small>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            taxa = (stats['cotacoes_aceitas'] / stats['total_cotacoes'] * 100) if stats['total_cotacoes'] > 0 else 0
            st.markdown(f"""
            <div class="metric-card">
                <div class="metric-label">Taxa de Sucesso</div>
                <div class="metric-value">{taxa:.1f}%</div>
                <small>Cotações aceitas</small>
            </div>
            """, unsafe_allow_html=True)
        
        # Minhas cotações recentes
        st.markdown("### 📝 Minhas Últimas Cotações")
        minhas_cotacoes = get_cotacoes_por_transportadora(st.session_state.usuario_id)
        
        if minhas_cotacoes:
            for cot in minhas_cotacoes[:5]:
                solicitacao = get_solicitacao_por_id(cot['solicitacao_id'])
                if solicitacao:
                    with st.expander(f"{cot['id']} - R$ {cot['valor_frete']:,.2f}"):
                        st.write(f"**Rota:** {solicitacao['local_coleta']} → {solicitacao['local_entrega']}")
                        st.write(f"**Status:** {cot['status']}")
                        st.write(f"**Enviada em:** {data_ptbr(cot['created_at'])}")
        else:
            st.info("Você ainda não enviou nenhuma cotação")

# =============================================
# NOVA SOLICITAÇÃO
# =============================================
elif menu == "➕ Nova Solicitação" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### ➕ Nova Solicitação de Frete")
    
    with st.form("nova_solicitacao"):
        col1, col2 = st.columns(2)
        
        with col1:
            local_coleta = st.text_input("📍 Local de Coleta*", placeholder="Ex: Piracicaba - SP")
            material = st.selectbox("📦 Material*", [
                "Eletrônicos", "Móveis", "Alimentos", "Químicos",
                "Automotivo", "Metais", "Plásticos", "Papel"
            ])
            data_coleta = st.date_input("📅 Data Coleta*", min_value=datetime.today())
            
        with col2:
            local_entrega = st.text_input("🎯 Local de Entrega*", placeholder="Ex: Salvador - BA")
            valor_carga = st.number_input("💰 Valor da Carga (R$)*", min_value=0.0, format="%.2f")
            data_entrega = st.date_input("📅 Data Entrega*", min_value=datetime.today())
        
        tomador = st.text_input("🏢 Tomador*", placeholder="Cliente final", value="C3 Engenharia")
        observacoes = st.text_area("📝 Observações", placeholder="Informações adicionais sobre a carga...")
        
        submitted = st.form_submit_button("🚀 Publicar Frete", use_container_width=True)
        
        if submitted:
            if not all([local_coleta, local_entrega, material, tomador]):
                show_toast("Preencha todos os campos obrigatórios", "error")
            elif data_coleta > data_entrega:
                show_toast("Data de coleta não pode ser maior que data de entrega", "error")
            else:
                with st.spinner("Publicando frete..."):
                    solicitacao_id = f"FRT-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
                    
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
                        'leilao_encerrado': False,
                        'created_at': datetime.now()
                    }
                    
                    if adicionar_solicitacao(solicitacao_dict):
                        show_toast(f"Frete {solicitacao_id} publicado com sucesso!", "success")
                        adicionar_log_seguranca(
                            st.session_state.usuario_id,
                            'NOVA_SOLICITACAO',
                            f'Frete: {local_coleta} → {local_entrega}',
                            st.session_state.get('ip', 'N/A')
                        )
                        time.sleep(1)
                        st.rerun()
                    else:
                        show_toast("Erro ao publicar frete", "error")

# =============================================
# GERENCIAR SOLICITAÇÕES
# =============================================
elif menu == "📋 Gerenciar Solicitações" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### 📋 Gerenciar Solicitações")
    
    try:
        minhas_solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        minhas_solicitacoes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        if minhas_solicitacoes:
            for sol in minhas_solicitacoes:
                leilao_status = "🔒 Leilão Encerrado" if sol.get('leilao_encerrado') else "🔄 Leilão Ativo"
                
                with st.expander(f"{sol['id']} - {sol['local_coleta']} → {sol['local_entrega']} - {leilao_status}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Material:** {sol['material']}")
                        st.write(f"**Valor da Carga:** R$ {sol['valor_carga']:,.2f}" if sol['valor_carga'] else "Não informado")
                        st.write(f"**Data Coleta:** {sol['data_coleta']}")
                        st.write(f"**Tomador:** {sol['tomador']}")
                    
                    with col2:
                        st.write(f"**Data Entrega:** {sol['data_entrega']}")
                        st.write(f"**Status:** {sol['status']}")
                        st.write(f"**Criada em:** {data_ptbr(sol['created_at'])}")
                        st.write(f"**Observações:** {sol['observacoes'] or 'Nenhuma'}")
                    
                    cotacoes_sol = get_cotacoes_por_solicitacao(sol['id'])
                    st.write(f"**Cotações recebidas:** {len(cotacoes_sol)}")
                    
                    if cotacoes_sol:
                        st.markdown("---")
                        st.markdown("#### Melhores Cotações")
                        cotacoes_ordenadas = sorted(cotacoes_sol, key=lambda x: x['valor_frete'])
                        for i, cot in enumerate(cotacoes_ordenadas[:5]):
                            posicao = i + 1
                            emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                            st.write(f"{emoji} **{cot['transportadora_nome']}** - R$ {cot['valor_frete']:,.2f}")
                    
                    st.markdown("---")
                    st.markdown("#### Excluir Solicitação")
                    
                    with st.form(f"excluir_sol_{sol['id']}"):
                        st.warning("⚠️ ATENÇÃO: Esta ação não pode ser desfeita!")
                        st.write("Serão excluídos: esta solicitação e todas as cotações relacionadas")
                        
                        confirmar = st.checkbox("Confirmar exclusão permanente", key=f"confirm_{sol['id']}")
                        
                        if st.form_submit_button("EXCLUIR SOLICITAÇÃO", disabled=not confirmar):
                            if excluir_solicitacao(sol['id']):
                                show_toast("Solicitação excluída com sucesso!", "success")
                                adicionar_log_seguranca(
                                    st.session_state.usuario_id,
                                    'EXCLUIR_SOLICITACAO',
                                    f'Solicitação: {sol["id"]}',
                                    st.session_state.get('ip', 'N/A')
                                )
                                time.sleep(1)
                                st.rerun()
                            else:
                                show_toast("Erro ao excluir solicitação", "error")
        else:
            st.info("Nenhuma solicitação criada ainda")
    except Exception as e:
        st.error(f"Erro ao carregar solicitações: {e}")

# =============================================
# COTAÇÕES RECEBIDAS
# =============================================
elif menu == "💰 Cotações Recebidas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### 💰 Cotações Recebidas")
    
    try:
        minhas_solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        todas_cotacoes = get_cotacoes()
        
        minhas_cotacoes = []
        for cot in todas_cotacoes:
            for sol in minhas_solicitacoes:
                if sol['id'] == cot['solicitacao_id']:
                    minhas_cotacoes.append({
                        **cot,
                        'local_coleta': sol['local_coleta'],
                        'local_entrega': sol['local_entrega'],
                        'material': sol['material'],
                        'leilao_encerrado': sol['leilao_encerrado']
                    })
                    break
        
        minhas_cotacoes.sort(key=lambda x: x['created_at'], reverse=True)
        
        if minhas_cotacoes:
            for cot in minhas_cotacoes:
                status_emoji = "✅" if cot['status'] == "Aceita" else "❌" if cot['status'] == "Recusada" else "⏳"
                editado = " (Editada)" if cot.get('updated_at') != cot.get('created_at') else ""
                
                with st.expander(f"{status_emoji} {cot['id']} - {cot['local_coleta']} → {cot['local_entrega']} - R$ {cot['valor_frete']:,.2f}{editado}"):
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.write(f"**Transportadora:** {cot['transportadora_nome']}")
                        st.write(f"**Material:** {cot['material']}")
                        st.write(f"**Valor do Frete:** R$ {cot['valor_frete']:,.2f}")
                    
                    with col2:
                        st.write(f"**Prazo:** {cot['prazo_entrega']}")
                        st.write(f"**Status:** {cot['status']}")
                        st.write(f"**Enviada em:** {data_ptbr(cot['created_at'])}")
                    
                    with col3:
                        st.write(f"**Observações:** {cot['observacoes'] or 'Nenhuma'}")
                        
                        if cot['status'] == "Pendente" and not cot['leilao_encerrado']:
                            col_aceitar, col_recusar = st.columns(2)
                            with col_aceitar:
                                if st.button("✅ Aceitar", key=f"aceitar_{cot['id']}"):
                                    if atualizar_cotacao(cot['id'], {'status': 'Aceita'}):
                                        show_toast(f"Cotação de {cot['transportadora_nome']} aceita!", "success")
                                        adicionar_log_seguranca(
                                            st.session_state.usuario_id,
                                            'COTACAO_ACEITA',
                                            f'Cotação: {cot["id"]}',
                                            st.session_state.get('ip', 'N/A')
                                        )
                                        time.sleep(1)
                                        st.rerun()
                            
                            with col_recusar:
                                if st.button("❌ Recusar", key=f"recusar_{cot['id']}"):
                                    if atualizar_cotacao(cot['id'], {'status': 'Recusada'}):
                                        show_toast("Cotação recusada", "warning")
                                        time.sleep(1)
                                        st.rerun()
        else:
            st.info("Nenhuma cotação recebida ainda")
    except Exception as e:
        st.error(f"Erro ao carregar cotações: {e}")

# =============================================
# ENCERRAR LEILÃO
# =============================================
elif menu == "🏆 Encerrar Leilão" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### 🏆 Encerrar Leilão e Selecionar Vencedor")
    st.warning("⚠️ Após encerrar o leilão, novas cotações não serão mais aceitas")
    
    try:
        minhas_solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
        solicitacoes_ativas = [s for s in minhas_solicitacoes if s['status'] == 'Aberta' and not s['leilao_encerrado']]
        
        if solicitacoes_ativas:
            for sol in solicitacoes_ativas:
                cotacoes_sol = get_cotacoes_por_solicitacao(sol['id'])
                cotacoes_ordenadas = sorted(cotacoes_sol, key=lambda x: x['valor_frete'])
                
                with st.expander(f"{sol['id']} - {sol['local_coleta']} → {sol['local_entrega']} - {len(cotacoes_sol)} cotações"):
                    st.write(f"**Material:** {sol['material']}")
                    st.write(f"**Valor da Carga:** R$ {sol['valor_carga']:,.2f}")
                    
                    if cotacoes_ordenadas:
                        st.markdown("#### Ranking das Cotações")
                        
                        for i, cot in enumerate(cotacoes_ordenadas):
                            posicao = i + 1
                            emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                            
                            if posicao == 1:
                                st.success(f"{emoji} **{cot['transportadora_nome']}** - R$ {cot['valor_frete']:,.2f} - {cot['prazo_entrega']}")
                            else:
                                st.write(f"{emoji} {cot['transportadora_nome']} - R$ {cot['valor_frete']:,.2f} - {cot['prazo_entrega']}")
                        
                        melhor_cotacao = cotacoes_ordenadas[0]
                        
                        col1, col2 = st.columns(2)
                        with col1:
                            st.info(f"**Melhor Cotação:** {melhor_cotacao['transportadora_nome']} - R$ {melhor_cotacao['valor_frete']:,.2f}")
                        with col2:
                            if st.button(f"🏆 Encerrar Leilão - Selecionar {melhor_cotacao['transportadora_nome']}", key=f"encerrar_{sol['id']}"):
                                if atualizar_cotacao(melhor_cotacao['id'], {'status': 'Aceita'}):
                                    if atualizar_solicitacao(sol['id'], {'status': 'Fechada', 'leilao_encerrado': True, 'vencedor_id': melhor_cotacao['transportadora_id'], 'valor_vencedor': melhor_cotacao['valor_frete']}):
                                        show_toast(f"Leilão encerrado! Vencedor: {melhor_cotacao['transportadora_nome']} - R$ {melhor_cotacao['valor_frete']:,.2f}", "success")
                                        adicionar_log_seguranca(
                                            st.session_state.usuario_id,
                                            'LEILAO_ENCERRADO',
                                            f'Solicitação {sol["id"]} vencedor: {melhor_cotacao["transportadora_nome"]}',
                                            st.session_state.get('ip', 'N/A')
                                        )
                                        time.sleep(2)
                                        st.rerun()
                    else:
                        st.warning("Nenhuma cotação recebida para este frete ainda")
        else:
            st.info("Não há leilões ativos para encerrar")
    except Exception as e:
        st.error(f"Erro ao carregar leilões: {e}")

# =============================================
# TRANSPORTADORAS CADASTRADAS
# =============================================
elif menu == "🚛 Transportadoras Cadastradas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### 🚛 Transportadoras Cadastradas")
    
    try:
        usuarios = get_usuarios()
        transportadoras = [u for u in usuarios if u['tipo'] == 'transportadora' and u['status'] == 'Ativa']
        
        if transportadoras:
            st.info(f"**Total de transportadoras:** {len(transportadoras)}")
            
            for transp in transportadoras:
                with st.expander(f"{transp['razao_social']}"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.write(f"**Razão Social:** {transp['razao_social']}")
                        st.write(f"**CNPJ:** ****{transp['cnpj_ultimos4']}")
                        st.write(f"**E-mail:** ****@****")
                    with col2:
                        st.write(f"**Telefone:** {transp['telefone']}")
                        st.write(f"**Cidade:** {transp['cidade']}")
                        st.write(f"**Data Cadastro:** {transp['data_cadastro']}")
        else:
            st.info("Nenhuma transportadora cadastrada")
    except Exception as e:
        st.error(f"Erro ao carregar transportadoras: {e}")

# =============================================
# FRETES DISPONÍVEIS (TRANSPORTADORA)
# =============================================
elif menu == "🚚 Fretes Disponíveis" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### 🚚 Fretes Disponíveis para Cotação")
    st.info("💡 **Como funciona:** Você vê apenas os valores das outras cotações, não os nomes. O menor valor vence! Você pode editar sua cotação a qualquer momento.")
    
    try:
        solicitacoes = get_solicitacoes()
        solicitacoes_abertas = [s for s in solicitacoes if s['status'] == 'Aberta' and not s['leilao_encerrado']]
        solicitacoes_abertas.sort(key=lambda x: x['created_at'], reverse=True)
        
        if solicitacoes_abertas:
            for sol in solicitacoes_abertas:
                cotacoes_existentes = get_cotacoes_por_solicitacao(sol['id'])
                minha_cotacao = None
                for cot in cotacoes_existentes:
                    if cot['transportadora_id'] == st.session_state.usuario_id:
                        minha_cotacao = cot
                        break
                
                cotacoes_ordenadas = sorted(cotacoes_existentes, key=lambda x: x['valor_frete'])
                
                with st.expander(f"{sol['id']} - {sol['local_coleta']} → {sol['local_entrega']} - {len(cotacoes_existentes)} cotações"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.write(f"**Material:** {sol['material']}")
                        st.write(f"**Valor da Carga:** R$ {sol['valor_carga']:,.2f}")
                        st.write(f"**Data Coleta:** {sol['data_coleta']}")
                    
                    with col2:
                        st.write(f"**Data Entrega:** {sol['data_entrega']}")
                        st.write(f"**Observações:** {sol['observacoes'] or 'Nenhuma'}")
                        st.write(f"**Publicada em:** {data_ptbr(sol['created_at'])}")
                    
                    if cotacoes_ordenadas:
                        st.markdown("---")
                        st.markdown("#### Ranking Atual de Cotações (Apenas valores)")
                        
                        for i, cot in enumerate(cotacoes_ordenadas[:5]):
                            posicao = i + 1
                            emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                            
                            if cot['transportadora_id'] == st.session_state.usuario_id:
                                st.success(f"{emoji} **R$ {cot['valor_frete']:,.2f}** - {cot['prazo_entrega']} (MINHA COTAÇÃO)")
                            else:
                                st.write(f"{emoji} **R$ {cot['valor_frete']:,.2f}** - {cot['prazo_entrega']}")
                    
                    st.markdown("---")
                    
                    with st.form(f"cotacao_form_{sol['id']}"):
                        st.markdown("#### Minha Cotação")
                        
                        valor_padrao = minha_cotacao['valor_frete'] if minha_cotacao else 0.0
                        prazo_padrao = minha_cotacao['prazo_entrega'] if minha_cotacao else '3 dias'
                        obs_padrao = minha_cotacao['observacoes'] if minha_cotacao else ''
                        
                        col_valor, col_prazo = st.columns(2)
                        
                        with col_valor:
                            valor_frete = st.number_input("Valor do Frete (R$)", min_value=0.01, format="%.2f", value=valor_padrao)
                        with col_prazo:
                            prazo_entrega = st.selectbox("Prazo de Entrega", ["2 dias", "3 dias", "4 dias", "5 dias", "1 semana"], index=["2 dias", "3 dias", "4 dias", "5 dias", "1 semana"].index(prazo_padrao) if prazo_padrao in ["2 dias", "3 dias", "4 dias", "5 dias", "1 semana"] else 1)
                        
                        observacoes = st.text_area("Observações", value=obs_padrao)
                        
                        if st.form_submit_button("Salvar Cotação" if minha_cotacao else "Enviar Cotação"):
                            if valor_frete <= 0:
                                show_toast("Informe um valor válido", "error")
                            else:
                                with st.spinner("Processando..."):
                                    if minha_cotacao:
                                        if atualizar_cotacao(minha_cotacao['id'], {
                                            'valor_frete': valor_frete,
                                            'prazo_entrega': prazo_entrega,
                                            'observacoes': observacoes
                                        }):
                                            show_toast("Cotação atualizada com sucesso!", "success")
                                            adicionar_log_seguranca(
                                                st.session_state.usuario_id,
                                                'COTACAO_EDITADA',
                                                f'Cotação para solicitação {sol["id"]}',
                                                st.session_state.get('ip', 'N/A')
                                            )
                                            time.sleep(1)
                                            st.rerun()
                                    else:
                                        cotacao_id = f"COT-{secrets.token_hex(4).upper()}"
                                        cotacao_dict = {
                                            'id': cotacao_id,
                                            'solicitacao_id': sol['id'],
                                            'transportadora_id': st.session_state.usuario_id,
                                            'transportadora_nome': st.session_state.razao_social,
                                            'valor_frete': valor_frete,
                                            'prazo_entrega': prazo_entrega,
                                            'observacoes': observacoes,
                                            'status': 'Pendente',
                                            'created_at': datetime.now(),
                                            'updated_at': datetime.now()
                                        }
                                        
                                        if adicionar_cotacao(cotacao_dict):
                                            show_toast("Cotação enviada com sucesso!", "success")
                                            adicionar_log_seguranca(
                                                st.session_state.usuario_id,
                                                'NOVA_COTACAO',
                                                f'Cotação para solicitação {sol["id"]}',
                                                st.session_state.get('ip', 'N/A')
                                            )
                                            time.sleep(1)
                                            st.rerun()
        else:
            st.info("Nenhum frete disponível para cotação no momento")
    except Exception as e:
        st.error(f"Erro ao carregar fretes: {e}")

# =============================================
# MINHAS COTAÇÕES (TRANSPORTADORA)
# =============================================
elif menu == "📝 Minhas Cotações" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### 📝 Minhas Cotações Enviadas")
    
    try:
        minhas_cotacoes = get_cotacoes_por_transportadora(st.session_state.usuario_id)
        minhas_cotacoes.sort(key=lambda x: x['created_at'], reverse=True)
        
        if minhas_cotacoes:
            for cot in minhas_cotacoes:
                solicitacao = get_solicitacao_por_id(cot['solicitacao_id'])
                
                if solicitacao:
                    status_emoji = "✅" if cot['status'] == "Aceita" else "❌" if cot['status'] == "Recusada" else "⏳"
                    editado = " (Editada)" if cot.get('updated_at') != cot.get('created_at') else ""
                    
                    with st.expander(f"{status_emoji} {cot['id']} - {solicitacao['local_coleta']} → {solicitacao['local_entrega']} - R$ {cot['valor_frete']:,.2f}{editado}"):
                        col1, col2 = st.columns(2)
                        
                        with col1:
                            st.write(f"**Material:** {solicitacao['material']}")
                            st.write(f"**Meu Valor:** R$ {cot['valor_frete']:,.2f}")
                            st.write(f"**Meu Prazo:** {cot['prazo_entrega']}")
                        
                        with col2:
                            st.write(f"**Status:** {cot['status']}")
                            st.write(f"**Enviada em:** {data_ptbr(cot['created_at'])}")
                            if cot.get('updated_at') != cot.get('created_at'):
                                st.write(f"**Editada em:** {data_ptbr(cot['updated_at'])}")
                            st.write(f"**Minhas Observações:** {cot['observacoes'] or 'Nenhuma'}")
                        
                        if cot['status'] == "Pendente" and not solicitacao['leilao_encerrado']:
                            if st.button("❌ Cancelar Cotação", key=f"cancelar_{cot['id']}"):
                                if excluir_cotacao(cot['id']):
                                    show_toast("Cotação cancelada com sucesso!", "success")
                                    adicionar_log_seguranca(
                                        st.session_state.usuario_id,
                                        'CANCELAR_COTACAO',
                                        f'Cotação: {cot["id"]}',
                                        st.session_state.get('ip', 'N/A')
                                    )
                                    time.sleep(1)
                                    st.rerun()
        else:
            st.info("Você ainda não enviou nenhuma cotação")
    except Exception as e:
        st.error(f"Erro ao carregar cotações: {e}")

# =============================================
# BACKUP DE DADOS
# =============================================
elif menu == "📁 Backup de Dados" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### 📁 Backup de Dados")
    
    st.info("Gerar backup completo de todas as suas solicitações e cotações em formato Excel.")
    
    if st.button("📊 GERAR BACKUP COMPLETO", type="primary", use_container_width=True):
        with st.spinner("Gerando arquivo de backup..."):
            try:
                solicitacoes = get_solicitacoes_por_usuario(st.session_state.usuario_id)
                todas_cotacoes = get_cotacoes()
                
                dados_excel = []
                
                for sol in solicitacoes:
                    dados_excel.append({
                        'Tipo': 'SOLICITAÇÃO',
                        'ID': sol['id'],
                        'Local Coleta': sol['local_coleta'],
                        'Local Entrega': sol['local_entrega'],
                        'Material': sol['material'],
                        'Valor Carga': f"R$ {sol['valor_carga']:,.2f}" if sol['valor_carga'] else '',
                        'Data Coleta': sol['data_coleta'],
                        'Data Entrega': sol['data_entrega'],
                        'Tomador': sol['tomador'],
                        'Observações': sol['observacoes'] or '',
                        'Status': sol['status'],
                        'Leilão Encerrado': 'Sim' if sol['leilao_encerrado'] else 'Não',
                        'Criado em': data_ptbr(sol['created_at'])
                    })
                
                for cot in todas_cotacoes:
                    solicitacao = get_solicitacao_por_id(cot['solicitacao_id'])
                    if solicitacao and solicitacao['usuario_id'] == st.session_state.usuario_id:
                        dados_excel.append({
                            'Tipo': 'COTAÇÃO',
                            'ID': cot['id'],
                            'Solicitação ID': cot['solicitacao_id'],
                            'Transportadora': cot['transportadora_nome'],
                            'Valor Frete': f"R$ {cot['valor_frete']:,.2f}",
                            'Prazo Entrega': cot['prazo_entrega'],
                            'Observações': cot['observacoes'] or '',
                            'Status': cot['status'],
                            'Criado em': data_ptbr(cot['created_at']),
                            'Editado em': data_ptbr(cot['updated_at']) if cot.get('updated_at') != cot.get('created_at') else '',
                            'Local Coleta': solicitacao['local_coleta'],
                            'Local Entrega': solicitacao['local_entrega']
                        })
                
                df = pd.DataFrame(dados_excel)
                data_atual = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
                filename = f"backup_c3_{data_atual}.xlsx"
                
                df.to_excel(filename, index=False, engine='openpyxl')
                
                with open(filename, "rb") as file:
                    st.download_button(
                        label="💾 BAIXAR ARQUIVO EXCEL",
                        data=file,
                        file_name=filename,
                        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                        type="primary",
                        use_container_width=True
                    )
                
                st.success(f"Backup gerado com sucesso! {len(dados_excel)} registros exportados.")
                adicionar_log_seguranca(
                    st.session_state.usuario_id,
                    'BACKUP_GERADO',
                    f'Arquivo: {filename}',
                    st.session_state.get('ip', 'N/A')
                )
                
            except Exception as e:
                show_toast(f"Erro ao gerar backup: {e}", "error")

# =============================================
# MEU PERFIL
# =============================================
elif menu == "⚙️ Meu Perfil":
    st.markdown("### ⚙️ Meu Perfil")
    
    usuario = get_usuario_por_id(st.session_state.usuario_id)
    
    if usuario:
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown(f"""
            <div class="card-profissional">
                <h4>Informações Pessoais</h4>
                <p><strong>Razão Social:</strong> {usuario['razao_social']}</p>
                <p><strong>Telefone:</strong> {usuario['telefone']}</p>
                <p><strong>Cidade:</strong> {usuario['cidade']}</p>
                <p><strong>Tipo:</strong> {'Solicitante' if usuario['tipo'] == 'solicitante' else 'Transportadora'}</p>
                <p><strong>Cadastro:</strong> {usuario['data_cadastro']}</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown("""
            <div class="card-profissional">
                <h4>Alterar Senha</h4>
                <p style="color: var(--text-secondary); font-size: 0.875rem;">
                    ⚠️ Use uma senha forte com pelo menos 10 caracteres, incluindo maiúsculas, minúsculas, números e símbolos.
                </p>
            </div>
            """, unsafe_allow_html=True)
            
            with st.form("alterar_senha"):
                senha_atual = st.text_input("Senha Atual", type="password")
                nova_senha = st.text_input("Nova Senha", type="password")
                confirmar = st.text_input("Confirmar Nova Senha", type="password")
                
                if st.form_submit_button("🔄 Atualizar Senha", use_container_width=True):
                    if not all([senha_atual, nova_senha, confirmar]):
                        show_toast("Preencha todos os campos", "error")
                    elif nova_senha != confirmar:
                        show_toast("As novas senhas não coincidem", "error")
                    else:
                        valida, msg = validar_senha_forte(nova_senha)
                        if not valida:
                            show_toast(msg, "error")
                        else:
                            session = get_session()
                            try:
                                usuario_obj = session.query(Usuario).filter_by(id=st.session_state.usuario_id).first()
                                if usuario_obj and verificar_senha(senha_atual, usuario_obj.senha_hash):
                                    usuario_obj.senha_hash = hash_senha(nova_senha)
                                    session.commit()
                                    show_toast("Senha alterada com sucesso!", "success")
                                    adicionar_log_seguranca(
                                        st.session_state.usuario_id,
                                        'ALTERAR_SENHA',
                                        'Senha alterada com sucesso',
                                        st.session_state.get('ip', 'N/A')
                                    )
                                else:
                                    show_toast("Senha atual incorreta", "error")
                            finally:
                                session.close()

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: var(--text-secondary); padding: 2rem;">
    <strong>🏆 C3 FREIGHTS - Sistema de Leilão de Fretes</strong><br>
    <small>🔒 Sistema seguro com criptografia de ponta a ponta | v2.0</small>
</div>
""", unsafe_allow_html=True)
