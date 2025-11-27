import streamlit as st
import pandas as pd
from datetime import datetime
import sqlite3
import uuid
import hashlib
import time
import re
import secrets
import string

# FUNÇÕES DE VALIDAÇÃO E SEGURANÇA
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
    
# CONFIGURAÇÃO PROFISSIONAL
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

# BANCO DE DADOS - VERSÃO SEGURA
def init_db():
    conn = sqlite3.connect('sistema_fretes.db', check_same_thread=False)
    c = conn.cursor()
        
    # TABELA DE USUÁRIOS/EMPRESAS (LOGIN)
    c.execute('''
        CREATE TABLE IF NOT EXISTS usuarios (
            id TEXT PRIMARY KEY,
            razao_social TEXT,
            cnpj TEXT UNIQUE,
            email TEXT,
            telefone TEXT,
            cidade TEXT,
            senha_hash TEXT,
            tipo TEXT DEFAULT 'transportadora',
            status TEXT DEFAULT 'Ativa',
            data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # TABELA DE LOGS DE SEGURANÇA
    c.execute('''
        CREATE TABLE IF NOT EXISTS logs_seguranca (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id TEXT,
            acao TEXT,
            descricao TEXT,
            ip TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # TABELA DE SOLICITAÇÕES
    c.execute('''
        CREATE TABLE IF NOT EXISTS solicitacoes (
            id TEXT PRIMARY KEY,
            local_coleta TEXT,
            local_entrega TEXT,
            material TEXT,
            valor_carga REAL,
            data_coleta TEXT,
            data_entrega TEXT,
            tomador TEXT,
            observacoes TEXT,
            status TEXT DEFAULT 'Aberta',
            usuario_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    c.execute('''
        CREATE TABLE IF NOT EXISTS cotacoes (
            id TEXT PRIMARY KEY,
            solicitacao_id TEXT,
            transportadora_id TEXT,
            transportadora_nome TEXT,
            valor_frete REAL,
            prazo_entrega TEXT,
            observacoes TEXT,
            status TEXT DEFAULT 'Pendente',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # CRIAR USUÁRIO PADRÃO DO SOLICITANTE (C3 Engenharia)
    senha_hash = hashlib.sha256("17Sort34Son_".encode()).hexdigest()
    c.execute('''
        INSERT OR IGNORE INTO usuarios 
        (id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo) 
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        "SOL-001", 
        "C3 Engenharia", 
        "12.345.678/0001-90", 
        "caroline.frasseto@c3engenharia.com.br", 
        "(19) 98931-4967", 
        "Santa Bárbara D'Oeste - SP", 
        senha_hash, 
        "solicitante"
    ))
    
    conn.commit()
    return conn

# FUNÇÃO PARA CORRIGIR USUÁRIO EXISTENTE
def corrigir_tipo_usuario():
    c = conn.cursor()
    c.execute('''
        UPDATE usuarios 
        SET tipo = 'solicitante' 
        WHERE razao_social = 'C3 Engenharia' AND tipo != 'solicitante'
    ''')
    conn.commit()

# FUNÇÃO DE LOGS DE SEGURANÇA
def registrar_log_seguranca(usuario_id, acao, descricao, ip="N/A", user_agent="N/A"):
    """Registra logs de segurança"""
    try:
        c = conn.cursor()
        c.execute('''
            INSERT INTO logs_seguranca (usuario_id, acao, descricao, ip, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (usuario_id, acao, descricao, ip, user_agent))
        conn.commit()
    except Exception as e:
        print(f"Erro ao registrar log: {e}")

# Inicializa o banco e corrige se necessário
conn = init_db()
corrigir_tipo_usuario()

# FUNÇÕES DE AUTENTICAÇÃO SEGURA
def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

def verificar_login(usuario_input, senha):
    """Verifica login com proteção contra SQL injection e brute force"""
    if not usuario_input or not senha:
        return None
        
    # Limita tentativas de login (proteção contra brute force)
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
        st.session_state.last_attempt = time.time()
    
    # Verifica se excedeu tentativas
    if st.session_state.login_attempts >= 5:
        tempo_restante = 300 - (time.time() - st.session_state.last_attempt)
        if tempo_restante > 0:
            st.error(f"Muitas tentativas de login. Tente novamente em {int(tempo_restante/60)} minutos")
            registrar_log_seguranca("SISTEMA", "TENTATIVAS_EXCEDIDAS", f"Usuário: {usuario_input}")
            return None
        else:
            st.session_state.login_attempts = 0
    
    try:
        c = conn.cursor()
        senha_hash = hash_senha(senha)
        
        # Query parametrizada (proteção contra SQL injection)
        c.execute('''
            SELECT * FROM usuarios 
            WHERE (cnpj = ? OR razao_social = ?) 
            AND senha_hash = ? 
            AND status = "Ativa"
        ''', (usuario_input, usuario_input, senha_hash))
        
        usuario = c.fetchone()
        
        if usuario:
            st.session_state.login_attempts = 0  # Reseta tentativas
            registrar_log_seguranca(usuario[0], "LOGIN_SUCESSO", f"Usuário: {usuario[1]}")
            return usuario
        else:
            st.session_state.login_attempts += 1
            st.session_state.last_attempt = time.time()
            registrar_log_seguranca("SISTEMA", "LOGIN_FALHA", f"Tentativa: {usuario_input}")
            return None
            
    except Exception as e:
        st.error("Erro no sistema de login")
        registrar_log_seguranca("SISTEMA", "ERRO_LOGIN", f"Erro: {str(e)}")
        return None

def cadastrar_usuario(razao_social, cnpj, email, telefone, cidade, senha, tipo='transportadora'):
    try:
        c = conn.cursor()
        usuario_id = f"USER-{uuid.uuid4().hex[:8].upper()}"
        senha_hash = hash_senha(senha)
        
        c.execute('''
            INSERT INTO usuarios (id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (usuario_id, razao_social, cnpj, email, telefone, cidade, senha_hash, tipo))
        conn.commit()
        
        registrar_log_seguranca("SISTEMA", "CADASTRO_USUARIO", f"Novo usuário: {razao_social}")
        return True
    except sqlite3.IntegrityError:
        return False

# FUNÇÕES DO SISTEMA
def get_estatisticas_solicitante():
    c = conn.cursor()
    
    c.execute("SELECT COUNT(*) FROM solicitacoes WHERE status = 'Aberta' AND usuario_id = 'SOL-001'")
    solicitacoes_ativas = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM usuarios WHERE tipo = 'transportadora' AND status = 'Ativa'")
    total_transportadoras = c.fetchone()[0]
    
    c.execute('''
        SELECT COUNT(*) FROM cotacoes c 
        JOIN solicitacoes s ON c.solicitacao_id = s.id 
        WHERE s.usuario_id = 'SOL-001'
    ''')
    total_cotacoes = c.fetchone()[0]
    
    c.execute('''
        SELECT COUNT(*) FROM cotacoes c 
        JOIN solicitacoes s ON c.solicitacao_id = s.id 
        WHERE s.usuario_id = 'SOL-001' AND DATE(c.created_at) = DATE('now')
    ''')
    cotacoes_hoje = c.fetchone()[0]
    
    return {
        'solicitacoes_ativas': solicitacoes_ativas or 0,
        'total_transportadoras': total_transportadoras or 0,
        'total_cotacoes': total_cotacoes or 0,
        'cotacoes_hoje': cotacoes_hoje or 0
    }

def excluir_solicitacao(solicitacao_id):
    """Exclui uma solicitação e todas as suas cotações"""
    try:
        c = conn.cursor()
        
        c.execute("SELECT id FROM solicitacoes WHERE id = ?", (solicitacao_id,))
        if not c.fetchone():
            raise Exception("Solicitação não encontrada")
        
        c.execute("DELETE FROM cotacoes WHERE solicitacao_id = ?", (solicitacao_id,))
        c.execute("DELETE FROM solicitacoes WHERE id = ?", (solicitacao_id,))
        
        conn.commit()
        registrar_log_seguranca(st.session_state.usuario_id, "EXCLUIR_SOLICITACAO", f"ID: {solicitacao_id}")
        return True
    except Exception as e:
        conn.rollback()
        raise e

def excluir_cotacao(cotacao_id):
    """Exclui uma cotação específica do sistema"""
    try:
        c = conn.cursor()
        
        c.execute("SELECT id FROM cotacoes WHERE id = ?", (cotacao_id,))
        if not c.fetchone():
            raise Exception("Cotação não encontrada")
        
        c.execute("DELETE FROM cotacoes WHERE id = ?", (cotacao_id,))
        conn.commit()
        
        registrar_log_seguranca(st.session_state.usuario_id, "EXCLUIR_COTACAO", f"ID: {cotacao_id}")
        return True
    except Exception as e:
        conn.rollback()
        raise e

# FUNÇÃO DE BACKUP
def gerar_backup_excel():
    """Gera um arquivo Excel com todas as solicitações e cotações"""
    try:
        c = conn.cursor()
        
        c.execute('''
            SELECT s.*, u.razao_social as usuario_nome
            FROM solicitacoes s 
            LEFT JOIN usuarios u ON s.usuario_id = u.id 
            WHERE s.usuario_id = ?
            ORDER BY s.created_at DESC
        ''', (st.session_state.usuario_id,))
        solicitacoes = c.fetchall()
        
        c.execute('''
            SELECT c.*, s.local_coleta, s.local_entrega, u.razao_social as transportadora_nome
            FROM cotacoes c 
            JOIN solicitacoes s ON c.solicitacao_id = s.id 
            JOIN usuarios u ON c.transportadora_id = u.id 
            WHERE s.usuario_id = ?
            ORDER BY c.created_at DESC
        ''', (st.session_state.usuario_id,))
        cotacoes = c.fetchall()
        
        dados_excel = []
        
        for sol in solicitacoes:
            dados_excel.append({
                'Tipo': 'SOLICITAÇÃO',
                'ID': sol[0],
                'Local Coleta': sol[1],
                'Local Entrega': sol[2],
                'Material': sol[3],
                'Valor Carga': f"R$ {sol[4]:,.2f}" if sol[4] else '',
                'Data Coleta': sol[5],
                'Data Entrega': sol[6],
                'Tomador': sol[7],
                'Observações': sol[8] or '',
                'Status': sol[9],
                'Criado em': data_ptbr(sol[11]),
                'Usuário': sol[12] or 'N/A'
            })
        
        for cot in cotacoes:
            dados_excel.append({
                'Tipo': 'COTAÇÃO',
                'ID': cot[0],
                'Solicitação ID': cot[1],
                'Transportadora': cot[9] or cot[3],
                'Valor Frete': f"R$ {cot[4]:,.2f}" if cot[4] else '',
                'Prazo Entrega': cot[5],
                'Observações': cot[6] or '',
                'Status': cot[7],
                'Criado em': data_ptbr(cot[8]),
                'Local Coleta': cot[10],
                'Local Entrega': cot[11]
            })
        
        df = pd.DataFrame(dados_excel)
        data_atual = datetime.now().strftime("%d-%m-%Y_%H-%M-%S")
        filename = f"backup_solicitacoes_{data_atual}.xlsx"
        
        df.to_excel(filename, index=False, engine='openpyxl')
        
        registrar_log_seguranca(st.session_state.usuario_id, "BACKUP_GERADO", f"Arquivo: {filename}")
        return filename, df
        
    except Exception as e:
        st.error(f"Erro ao gerar backup: {str(e)}")
        return None, None

# SISTEMA DE LOGIN SEGURO
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
            cnpj = st.text_input("Usuário", placeholder="Digite seu usuário")
            senha = st.text_input("Senha", type="password", placeholder="Digite sua senha")
            submit_login = st.form_submit_button("Entrar no Sistema")
            
            if submit_login:
                if cnpj and senha:
                    usuario = verificar_login(cnpj, senha)
                    if usuario:
                        st.session_state.logged_in = True
                        st.session_state.usuario_id = usuario[0]
                        st.session_state.razao_social = usuario[1]
                        st.session_state.tipo_usuario = usuario[7]
                        st.success(f"Bem-vindo, {usuario[1]}!")
                        st.rerun()
                    else:
                        st.error("Usuário ou senha incorretos")
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
                        st.success("Transportadora cadastrada com sucesso! Aguarde aprovação.")
                    else:
                        st.error("CNPJ já cadastrado no sistema")

# VERIFICAÇÕES DE SEGURANÇA ANTES DO SISTEMA PRINCIPAL
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    mostrar_login()
    st.stop()

# VERIFICAÇÃO DE SEGURANÇA - SESSÃO VÁLIDA
if st.session_state.logged_in:
    c = conn.cursor()
    c.execute("SELECT id, status FROM usuarios WHERE id = ?", (st.session_state.usuario_id,))
    usuario_valido = c.fetchone()
    
    if not usuario_valido:
        st.error("Sessão inválida. Faça login novamente.")
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    
    if usuario_valido[1] != "Ativa":
        st.error("Sua conta está desativada.")
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

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
        registrar_log_seguranca(st.session_state.usuario_id, "LOGOUT", "Usuário desconectado")
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
            stats = get_estatisticas_solicitante()
        
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
        c = conn.cursor()
        
        try:
            c.execute('''
                SELECT c.id, c.transportadora_nome, c.valor_frete, c.prazo_entrega, c.created_at, s.local_coleta, s.local_entrega
                FROM cotacoes c 
                JOIN solicitacoes s ON c.solicitacao_id = s.id 
                WHERE s.usuario_id = 'SOL-001'
                ORDER BY c.created_at DESC LIMIT 5
            ''')
            ultimas_cotacoes = c.fetchall()
            
            if ultimas_cotacoes:
                st.markdown("#### Últimas Cotações Recebidas")
                for cot in ultimas_cotacoes:
                    tempo = tempo_desde(cot[4])
                    st.info(f"**{cot[1]}** - R$ {cot[2]:,.2f} - {cot[5]} → {cot[6]} - {tempo}")
            else:
                st.info("Nenhuma cotação recebida ainda")
        except sqlite3.OperationalError:
            st.info("Nenhuma cotação recebida ainda")
            
    else:
        # Dashboard para Transportadora
        st.markdown(f"### Dashboard - {st.session_state.razao_social}")
        
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM cotacoes WHERE transportadora_id = ?", (st.session_state.usuario_id,))
        minhas_cotacoes = c.fetchone()[0] or 0
        
        c.execute("SELECT COUNT(*) FROM cotacoes WHERE transportadora_id = ? AND status = 'Aceita'", (st.session_state.usuario_id,))
        cotacoes_aceitas = c.fetchone()[0] or 0
        
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f'<div class="metric-card">Cotações Enviadas<br><h3>{minhas_cotacoes}</h3></div>', unsafe_allow_html=True)
        with col2:
            st.markdown(f'<div class="metric-card">Cotações Aceitas<br><h3>{cotacoes_aceitas}</h3></div>', unsafe_allow_html=True)

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
                c = conn.cursor()
                c.execute('''
                    INSERT INTO solicitacoes (id, local_coleta, local_entrega, material, valor_carga, data_coleta, data_entrega, tomador, observacoes, usuario_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (solicitacao_id, local_coleta, local_entrega, material, valor_carga, 
                      data_coleta.strftime('%Y-%m-%d'), data_entrega.strftime('%Y-%m-%d'), tomador, observacoes, st.session_state.usuario_id))
                conn.commit()
                st.success(f"Solicitação {solicitacao_id} publicada com sucesso!")
            else:
                st.error("Preencha todos os campos obrigatórios")

# =============================================
# GERENCIAR SOLICITAÇÕES (COM EXCLUSÃO)
# =============================================
elif menu == "Gerenciar Solicitações" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Gerenciar Solicitações")
    
    try:
        c = conn.cursor()
        c.execute("SELECT * FROM solicitacoes WHERE usuario_id = ? ORDER BY created_at DESC", (st.session_state.usuario_id,))
        solicitacoes = c.fetchall()
        
        if solicitacoes:
            for sol in solicitacoes:
                with st.expander(f"{sol[0]} - {sol[1]} → {sol[2]} - {sol[9]}"):
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        st.markdown(f"**Material:** {sol[3]}")
                        st.markdown(f"**Valor da Carga:** R$ {sol[4]:,.2f}")
                        st.markdown(f"**Data Coleta:** {sol[5]}")
                        st.markdown(f"**Tomador:** {sol[7]}")
                    
                    with col2:
                        st.markdown(f"**Data Entrega:** {sol[6]}")
                        st.markdown(f"**Status:** {sol[9]}")
                        st.markdown(f"**Criada em:** {data_ptbr(sol[11])}")
                        st.markdown(f"**Observações:** {sol[8] if sol[8] else 'Nenhuma'}")
                    
                    # CONTAR COTAÇÕES
                    c2 = conn.cursor()
                    c2.execute("SELECT COUNT(*) FROM cotacoes WHERE solicitacao_id = ?", (sol[0],))
                    total_cotacoes = c2.fetchone()[0] or 0
                    st.markdown(f"**Cotações recebidas:** {total_cotacoes}")
                    
                    st.markdown("---")
                    st.markdown("#### Excluir Solicitação")
                    
                    with st.form(f"excluir_sol_{sol[0]}"):
                        st.markdown('<div class="danger-zone">', unsafe_allow_html=True)
                        st.error("ATENÇÃO: Esta ação não pode ser desfeita!")
                        st.write("Serão excluídos:")
                        st.write("- Esta solicitação")
                        st.write("- Todas as cotações relacionadas")
                        
                        confirmar = st.checkbox("Confirmar exclusão permanente", key=f"confirm_{sol[0]}")
                        confirmar2 = st.checkbox("Estou ciente que esta ação é irreversível", key=f"confirm2_{sol[0]}")
                        
                        if st.form_submit_button("EXCLUIR SOLICITAÇÃO", 
                                               disabled=not (confirmar and confirmar2),
                                               type="secondary"):
                            try:
                                excluir_solicitacao(sol[0])
                                st.success("Solicitação excluída com sucesso!")
                                time.sleep(2)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Erro ao excluir: {str(e)}")
                        st.markdown('</div>', unsafe_allow_html=True)
        else:
            st.info("Nenhuma solicitação criada ainda")
    except sqlite3.OperationalError:
        st.info("Nenhuma solicitação criada ainda")

# =============================================
# COTAÇÕES RECEBIDAS (COM EXCLUSÃO)
# =============================================
elif menu == "Cotações Recebidas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Cotações Recebidas")
    
    try:
        c = conn.cursor()
        c.execute('''
            SELECT c.*, s.local_coleta, s.local_entrega, s.material, s.valor_carga
            FROM cotacoes c 
            JOIN solicitacoes s ON c.solicitacao_id = s.id 
            WHERE s.usuario_id = ?
            ORDER BY c.created_at DESC
        ''', (st.session_state.usuario_id,))
        cotacoes = c.fetchall()
        
        if cotacoes:
            # Estatísticas
            total_cotacoes = len(cotacoes)
            cotacoes_aceitas = sum(1 for cot in cotacoes if cot[7] == "Aceita")
            cotacoes_pendentes = sum(1 for cot in cotacoes if cot[7] == "Pendente")
            
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total de Cotações", total_cotacoes)
            with col2:
                st.metric("Cotações Pendentes", cotacoes_pendentes)
            with col3:
                st.metric("Cotações Aceitas", cotacoes_aceitas)
            
            st.markdown("---")
            
            for i, cot in enumerate(cotacoes):
                # Definir estilo baseado no status
                if cot[7] == "Aceita":
                    status_emoji = "✅"
                    border_color = "4px solid #10b981"
                elif cot[7] == "Recusada":
                    status_emoji = "❌"
                    border_color = "4px solid #ef4444"
                else:
                    status_emoji = "⏳"
                    border_color = "4px solid #3b82f6"
                
                with st.expander(f"{status_emoji} {cot[0]} - {cot[9]} → {cot[10]} - R$ {cot[4]:,.2f}", expanded=False):
                    # Card com borda colorida
                    st.markdown(f"""
                    <div style="border-left: {border_color}; padding-left: 1rem; margin-bottom: 1rem;">
                        <h4>Cotação {cot[0]} - Status: {cot[7]}</h4>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    col1, col2, col3 = st.columns(3)
                    
                    with col1:
                        st.markdown("**Informações da Transportadora**")
                        st.markdown(f"**Empresa:** {cot[3]}")
                        st.markdown(f"**Solicitação:** {cot[1]}")
                        st.markdown(f"**Material:** {cot[11]}")
                        st.markdown(f"**Valor da Carga:** R$ {cot[12]:,.2f}")
                    
                    with col2:
                        st.markdown("**Detalhes da Cotação**")
                        st.markdown(f"**Valor do Frete:** R$ {cot[4]:,.2f}")
                        st.markdown(f"**Prazo:** {cot[5]}")
                        st.markdown(f"**Status:** {cot[7]}")
                        st.markdown(f"**Enviada em:** {data_ptbr(cot[8])}")
                    
                    with col3:
                        st.markdown("**Observações**")
                        st.markdown(f"**Observações:** {cot[6] if cot[6] else 'Nenhuma'}")
                        
                        # BOTÕES DE AÇÃO
                        st.markdown("**Ações Rápidas**")
                        
                        if cot[7] == "Pendente":
                            col_aceitar, col_recusar = st.columns(2)
                            with col_aceitar:
                                if st.button("Aceitar", key=f"aceitar_{cot[0]}_{i}", use_container_width=True):
                                    c2 = conn.cursor()
                                    c2.execute("UPDATE cotacoes SET status = 'Aceita' WHERE id = ?", (cot[0],))
                                    conn.commit()
                                    st.success("Cotação aceita com sucesso!")
                                    time.sleep(1)
                                    st.rerun()
                            
                            with col_recusar:
                                if st.button("Recusar", key=f"recusar_{cot[0]}_{i}", use_container_width=True):
                                    c2 = conn.cursor()
                                    c2.execute("UPDATE cotacoes SET status = 'Recusada' WHERE id = ?", (cot[0],))
                                    conn.commit()
                                    st.error("Cotação recusada!")
                                    time.sleep(1)
                                    st.rerun()
                        else:
                            st.info(f"Cotação já {cot[7].lower()}")
                    
                    # EXCLUSÃO DE COTAÇÃO
                    st.markdown("---")
                    st.markdown("#### Excluir Cotação")
                    
                    with st.form(f"excluir_cot_{cot[0]}_{i}"):
                        st.warning("**ATENÇÃO:** Esta ação não pode ser desfeita. A cotação será removida permanentemente do sistema.")
                        
                        confirmar1 = st.checkbox("Entendo que esta ação é permanente", key=f"confirm1_{cot[0]}_{i}")
                        confirmar2 = st.checkbox("Desejo realmente excluir esta cotação", key=f"confirm2_{cot[0]}_{i}")
                        
                        if st.form_submit_button("EXCLUIR COTAÇÃO", 
                                               disabled=not (confirmar1 and confirmar2),
                                               type="secondary"):
                            try:
                                excluir_cotacao(cot[0])
                                st.success("Cotação excluída com sucesso!")
                                time.sleep(1)
                                st.rerun()
                            except Exception as e:
                                st.error(f"Erro ao excluir cotação: {str(e)}")
        else:
            st.info("Nenhuma cotação recebida ainda")
            
    except sqlite3.OperationalError as e:
        st.error(f"Erro no banco de dados: {str(e)}")
        st.info("Tente recarregar a página ou verificar a conexão com o banco de dados.")

# =============================================
# TRANSPORTADORAS CADASTRADAS (SOLICITANTE)
# =============================================
elif menu == "Transportadoras Cadastradas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Transportadoras Cadastradas")
    
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE tipo = 'transportadora' AND status = 'Ativa'")
    transportadoras = c.fetchall()
    
    if transportadoras:
        st.info(f"**Total de transportadoras:** {len(transportadoras)}")
        
        for transp in transportadoras:
            with st.expander(f"{transp[1]}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Razão Social:** {transp[1]}")
                    st.markdown(f"**CNPJ:** {transp[2]}")
                    st.markdown(f"**E-mail:** {transp[3]}")
                with col2:
                    st.markdown(f"**Telefone:** {transp[4]}")
                    st.markdown(f"**Cidade:** {transp[5]}")
                    st.markdown(f"**Data Cadastro:** {transp[9]}")
    else:
        st.info("Nenhuma transportadora cadastrada")

# =============================================
# FRETES DISPONÍVEIS (PARA TRANSPORTADORAS)
# =============================================
elif menu == "Fretes Disponíveis" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### Fretes Disponíveis para Cotação")
    
    # Buscar solicitações abertas
    c = conn.cursor()
    c.execute("SELECT * FROM solicitacoes WHERE status = 'Aberta' ORDER BY created_at DESC")
    solicitacoes = c.fetchall()
    
    if solicitacoes:
        st.info(f"**Total de fretes disponíveis:** {len(solicitacoes)}")
        
        for sol in solicitacoes:
            # Buscar cotações existentes para mostrar ranking (sem nomes)
            c2 = conn.cursor()
            c2.execute('''
                SELECT valor_frete, prazo_entrega, created_at 
                FROM cotacoes 
                WHERE solicitacao_id = ? 
                ORDER BY valor_frete ASC
            ''', (sol[0],))
            cotacoes_existentes = c2.fetchall()
            
            with st.expander(f"{sol[0]} - {sol[1]} → {sol[2]} - {len(cotacoes_existentes)} cotações"):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Material:** {sol[3]}")
                    st.markdown(f"**Valor da Carga:** R$ {sol[4]:,.2f}")
                    st.markdown(f"**Data Coleta:** {sol[5]}")
                    st.markdown(f"**Tomador:** {sol[7]}")
                
                with col2:
                    st.markdown(f"**Data Entrega:** {sol[6]}")
                    st.markdown(f"**Observações:** {sol[8] if sol[8] else 'Nenhuma'}")
                    st.markdown(f"**Publicada em:** {data_ptbr(sol[11])}")
                
                # LEILÃO REVERSO - MOSTRAR COTAÇÕES EXISTENTES (SEM NOMES)
                if cotacoes_existentes:
                    st.markdown("---")
                    st.markdown("#### Ranking Atual de Cotações")
                    
                    for i, cot in enumerate(cotacoes_existentes[:5]):
                        posicao = i + 1
                        emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                        
                        tempo = tempo_desde(cot[2])
                        
                        st.markdown(f"{emoji} **R$ {cot[0]:,.2f}** | {cot[1]} | {tempo}")
                    
                    if len(cotacoes_existentes) > 5:
                        st.info(f"... e mais {len(cotacoes_existentes) - 5} cotações")
                
                # FORMULÁRIO PARA ENVIAR COTAÇÃO
                st.markdown("---")
                with st.form(f"cotacao_form_{sol[0]}"):
                    st.markdown("#### Enviar Minha Cotação")
                    
                    col_valor, col_prazo = st.columns(2)
                    with col_valor:
                        valor_frete = st.number_input("Meu Valor (R$)", min_value=0.0, format="%.2f", key=f"valor_{sol[0]}")
                    with col_prazo:
                        prazo_entrega = st.selectbox("Meu Prazo", ["2 dias", "3 dias", "4 dias", "5 dias", "1 semana"], key=f"prazo_{sol[0]}")
                    
                    observacoes = st.text_area("Minhas Observações", placeholder="Condições especiais, observações...", key=f"obs_{sol[0]}")
                    
                    submitted = st.form_submit_button("Enviar Cotação")
                    
                    if submitted:
                        if valor_frete > 0:
                            # Verificar se já existe cotação desta transportadora para esta solicitação
                            c2 = conn.cursor()
                            c2.execute("SELECT COUNT(*) FROM cotacoes WHERE solicitacao_id = ? AND transportadora_id = ?", 
                                     (sol[0], st.session_state.usuario_id))
                            ja_cotou = c2.fetchone()[0]
                            
                            if ja_cotou:
                                st.error("Você já enviou uma cotação para este frete!")
                            else:
                                cotacao_id = f"COT-{uuid.uuid4().hex[:8].upper()}"
                                c2.execute('''
                                    INSERT INTO cotacoes (id, solicitacao_id, transportadora_id, transportadora_nome, valor_frete, prazo_entrega, observacoes)
                                    VALUES (?, ?, ?, ?, ?, ?, ?)
                                ''', (cotacao_id, sol[0], st.session_state.usuario_id, st.session_state.razao_social, valor_frete, prazo_entrega, observacoes))
                                conn.commit()
                                st.success("Cotação enviada com sucesso! Agora outras empresas verão seu valor (sem seu nome)")
                                time.sleep(1)
                                st.rerun()
                        else:
                            st.error("Informe um valor válido para o frete")
    else:
        st.info("Nenhum frete disponível para cotação no momento")

# =============================================
# MINHAS COTAÇÕES (TRANSPORTADORAS)
# =============================================
elif menu == "Minhas Cotações" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### Minhas Cotações Enviadas")
    
    c = conn.cursor()
    c.execute('''
        SELECT c.*, s.local_coleta, s.local_entrega, s.material, s.status as status_solicitacao
        FROM cotacoes c 
        JOIN solicitacoes s ON c.solicitacao_id = s.id 
        WHERE c.transportadora_id = ?
        ORDER BY c.created_at DESC
    ''', (st.session_state.usuario_id,))
    minhas_cotacoes = c.fetchall()
    
    if minhas_cotacoes:
        st.info(f"**Total de cotações enviadas:** {len(minhas_cotacoes)}")
        
        # Estatísticas rápidas
        cotações_aceitas = sum(1 for cot in minhas_cotacoes if cot[7] == "Aceita")
        cotações_pendentes = sum(1 for cot in minhas_cotacoes if cot[7] == "Pendente")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Cotações Ativas", cotações_pendentes)
        with col2:
            st.metric("Cotações Aceitas", cotações_aceitas)
        with col3:
            taxa_sucesso = (cotações_aceitas / len(minhas_cotacoes)) * 100 if minhas_cotacoes else 0
            st.metric("Taxa de Sucesso", f"{taxa_sucesso:.1f}%")
        
        for cot in minhas_cotacoes:
            # Definir cores e emojis baseados no status
            if cot[7] == "Aceita":
                status_color = "✅"
                status_text = "Cotação Aceita"
                border_color = "2px solid #10b981"
            elif cot[7] == "Recusada":
                status_color = "❌"
                status_text = "Cotação Recusada"
                border_color = "2px solid #ef4444"
            else:
                status_color = "⏳"
                status_text = "Aguardando Avaliação"
                border_color = "2px solid #f59e0b"
            
            with st.expander(f"{status_color} {cot[0]} - {cot[8]} → {cot[9]} - R$ {cot[4]:,.2f}"):
                # Card com borda colorida baseada no status
                st.markdown(f"""
                <div style="border-left: {border_color}; padding-left: 1rem; margin-bottom: 1rem;">
                    <h4>{status_text}</h4>
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Material:** {cot[10]}")
                    st.markdown(f"**Meu Valor:** R$ {cot[4]:,.2f}")
                    st.markdown(f"**Meu Prazo:** {cot[5]}")
                    st.markdown(f"**Status da Solicitação:** {cot[11]}")
                
                with col2:
                    st.markdown(f"**Solicitação:** {cot[1]}")
                    st.markdown(f"**Data Envio:** {data_ptbr(cot[8])}")
                    st.markdown(f"**Minhas Observações:** {cot[6] if cot[6] else 'Nenhuma'}")
                    
                    # Botão para cancelar cotação se ainda estiver pendente
                    if cot[7] == "Pendente":
                        st.markdown("---")
                        if st.button("Cancelar Cotação", key=f"cancelar_{cot[0]}"):
                            c2 = conn.cursor()
                            c2.execute("DELETE FROM cotacoes WHERE id = ?", (cot[0],))
                            conn.commit()
                            st.success("Cotação cancelada com sucesso!")
                            time.sleep(1)
                            st.rerun()
                
                # VER RANKING ATUAL DESSA SOLICITAÇÃO
                st.markdown("---")
                if st.button("Ver Ranking Atual", key=f"ranking_{cot[0]}"):
                    c_ranking = conn.cursor()
                    c_ranking.execute('''
                        SELECT valor_frete, prazo_entrega, created_at 
                        FROM cotacoes 
                        WHERE solicitacao_id = ? 
                        ORDER BY valor_frete ASC
                    ''', (cot[1],))
                    ranking = c_ranking.fetchall()
                    
                    if ranking:
                        st.markdown("#### Ranking Atual (Menor Valor)")
                        for i, rank in enumerate(ranking[:5]):
                            posicao = i + 1
                            #emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                            
                            # Destacar minha cotação
                            if rank[0] == cot[4] and rank[1] == cot[5]:
                                st.markdown(f"**{emoji} R$ {rank[0]:,.2f} | {rank[1]} | MINHA COTAÇÃO**")
                            else:
                                st.markdown(f"{emoji} R$ {rank[0]:,.2f} | {rank[1]}")
    else:
        st.info("Você ainda não enviou nenhuma cotação")

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
                filename, df = gerar_backup_excel()
                
                if filename and df is not None:
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
                        
            except Exception as e:
                st.error(f"Erro ao gerar backup: {str(e)}")
    
    # Estatísticas rápidas
    st.markdown("---")
    st.markdown("### Estatísticas do Backup")
    
    try:
        c = conn.cursor()
        
        # Contar solicitações
        c.execute("SELECT COUNT(*) FROM solicitacoes WHERE usuario_id = ?", (st.session_state.usuario_id,))
        total_solicitacoes = c.fetchone()[0] or 0
        
        # Contar cotações
        c.execute('''
            SELECT COUNT(*) FROM cotacoes c 
            JOIN solicitacoes s ON c.solicitacao_id = s.id 
            WHERE s.usuario_id = ?
        ''', (st.session_state.usuario_id,))
        total_cotacoes = c.fetchone()[0] or 0
        
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
    
    c = conn.cursor()
    c.execute("SELECT * FROM usuarios WHERE id = ?", (st.session_state.usuario_id,))
    usuario = c.fetchone()
    
    if usuario:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**Razão Social:** {usuario[1]}")
            st.markdown(f"**CNPJ:** {usuario[2]}")
            st.markdown(f"**E-mail:** {usuario[3]}")
        with col2:
            st.markdown(f"**Telefone:** {usuario[4]}")
            st.markdown(f"**Cidade:** {usuario[5]}")
            st.markdown(f"**Tipo:** {'Solicitante' if usuario[7] == 'solicitante' else 'Transportadora'}")
            st.markdown(f"**Data Cadastro:** {usuario[9]}")
        
        st.markdown("---")
        st.markdown("### Alterar Senha")
        with st.form("alterar_senha"):
            senha_atual = st.text_input("Senha Atual", type="password")
            nova_senha = st.text_input("Nova Senha", type="password")
            confirmar_senha = st.text_input("Confirmar Nova Senha", type="password")
            
            if st.form_submit_button("Atualizar Senha"):
                if senha_atual and nova_senha and confirmar_senha:
                    if hash_senha(senha_atual) == usuario[6]:
                        if nova_senha == confirmar_senha:
                            c.execute("UPDATE usuarios SET senha_hash = ? WHERE id = ?", (hash_senha(nova_senha), st.session_state.usuario_id))
                            conn.commit()
                            st.success("Senha atualizada com sucesso!")
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
