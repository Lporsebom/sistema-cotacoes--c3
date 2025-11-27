import streamlit as st
import pandas as pd
from datetime import datetime
import uuid
import hashlib
import time
import re
import secrets
import string
import gspread
from google.oauth2.service_account import Credentials

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

# CONFIGURAÇÃO GOOGLE SHEETS - SUBSTITUI O SQLITE
def setup_google_sheets():
    """Configura a conexão com Google Sheets"""
    try:
        # Criar as credenciais a partir dos secrets do Streamlit
        creds_dict = {
            "type": "service_account",
            "project_id": st.secrets["gcp_service_account"]["project_id"],
            "private_key_id": st.secrets["gcp_service_account"]["private_key_id"],
            "private_key": st.secrets["gcp_service_account"]["private_key"],
            "client_email": st.secrets["gcp_service_account"]["client_email"],
            "client_id": st.secrets["gcp_service_account"]["client_id"],
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs"
        }
        
        scopes = ['https://www.googleapis.com/auth/spreadsheets']
        credentials = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        gc = gspread.authorize(credentials)
        
        # Abrir a planilha (será criada automaticamente se não existir)
        try:
            spreadsheet = gc.open("Sistema_Cotacoes_C3")
        except gspread.SpreadsheetNotFound:
            # Criar nova planilha se não existir
            spreadsheet = gc.create("Sistema_Cotacoes_C3")
            spreadsheet.share(st.secrets["gcp_service_account"]["client_email"], perm_type='user', role='writer')
        
        # CRIAR AS ABAS (TABELAS) SE NÃO EXISTIREM
        abas_necessarias = ['usuarios', 'logs_seguranca', 'solicitacoes', 'cotacoes']
        abas_existentes = [worksheet.title for worksheet in spreadsheet.worksheets()]
        
        for aba in abas_necessarias:
            if aba not in abas_existentes:
                worksheet = spreadsheet.add_worksheet(title=aba, rows=1000, cols=20)
                # Adicionar cabeçalhos baseado no tipo de aba
                if aba == 'usuarios':
                    worksheet.append_row([
                        'id', 'razao_social', 'cnpj', 'email', 'telefone', 'cidade', 
                        'senha_hash', 'tipo', 'status', 'data_cadastro'
                    ])
                elif aba == 'logs_seguranca':
                    worksheet.append_row([
                        'id', 'usuario_id', 'acao', 'descricao', 'ip', 'user_agent', 'created_at'
                    ])
                elif aba == 'solicitacoes':
                    worksheet.append_row([
                        'id', 'local_coleta', 'local_entrega', 'material', 'valor_carga', 
                        'data_coleta', 'data_entrega', 'tomador', 'observacoes', 'status', 
                        'usuario_id', 'created_at'
                    ])
                elif aba == 'cotacoes':
                    worksheet.append_row([
                        'id', 'solicitacao_id', 'transportadora_id', 'transportadora_nome', 
                        'valor_frete', 'prazo_entrega', 'observacoes', 'status', 'created_at'
                    ])
        
        # CRIAR USUÁRIO PADRÃO DO SOLICITANTE (C3 Engenharia) SE NÃO EXISTIR
        worksheet_usuarios = spreadsheet.worksheet('usuarios')
        usuarios_existentes = worksheet_usuarios.get_all_records()
        
        usuario_c3_existe = any(usuario.get('cnpj') == "12.345.678/0001-90" for usuario in usuarios_existentes)
        
        if not usuario_c3_existe:
            senha_hash = hashlib.sha256("17Sort34Son_".encode()).hexdigest()
            worksheet_usuarios.append_row([
                "SOL-001", 
                "C3 Engenharia", 
                "12.345.678/0001-90", 
                "caroline.frasseto@c3engenharia.com.br", 
                "(19) 98931-4967", 
                "Santa Bárbara D'Oeste - SP", 
                senha_hash, 
                "solicitante",
                "Ativa",
                datetime.now().strftime('%d-%m-%Y %H:%M:%S')
            ])
        
        return spreadsheet
        
    except Exception as e:
        st.error(f"Erro na configuração do Google Sheets: {e}")
        return None

# Inicializar Google Sheets
spreadsheet = setup_google_sheets()

# Funções auxiliares para trabalhar com Google Sheets
def get_worksheet_data(worksheet_name):
    """Obtém todos os dados de uma aba como lista de dicionários"""
    try:
        if spreadsheet:
            worksheet = spreadsheet.worksheet(worksheet_name)
            return worksheet.get_all_records()
        return []
    except Exception as e:
        st.error(f"Erro ao acessar aba {worksheet_name}: {e}")
        return []

def append_to_worksheet(worksheet_name, data):
    """Adiciona uma nova linha a uma aba"""
    try:
        if spreadsheet:
            worksheet = spreadsheet.worksheet(worksheet_name)
            worksheet.append_row(data)
            return True
        return False
    except Exception as e:
        st.error(f"Erro ao adicionar dados na aba {worksheet_name}: {e}")
        return False

def update_worksheet_row(worksheet_name, search_column, search_value, update_data):
    """Atualiza uma linha específica em uma aba"""
    try:
        if spreadsheet:
            worksheet = spreadsheet.worksheet(worksheet_name)
            records = worksheet.get_all_records()
            
            for i, record in enumerate(records, start=2):  # start=2 porque linha 1 é cabeçalho
                if str(record.get(search_column, '')).strip() == str(search_value).strip():
                    # Atualizar a linha
                    for col_index, value in enumerate(update_data, start=1):
                        worksheet.update_cell(i, col_index, value)
                    return True
            return False
    except Exception as e:
        st.error(f"Erro ao atualizar dados na aba {worksheet_name}: {e}")
        return False

def delete_worksheet_row(worksheet_name, search_column, search_value):
    """Exclui uma linha específica de uma aba"""
    try:
        if spreadsheet:
            worksheet = spreadsheet.worksheet(worksheet_name)
            records = worksheet.get_all_records()
            
            for i, record in enumerate(records, start=2):
                if str(record.get(search_column, '')).strip() == str(search_value).strip():
                    worksheet.delete_rows(i)
                    return True
            return False
    except Exception as e:
        st.error(f"Erro ao excluir dados na aba {worksheet_name}: {e}")
        return False

# FUNÇÃO DE LOGS DE SEGURANÇA ATUALIZADA
def registrar_log_seguranca(usuario_id, acao, descricao, ip="N/A", user_agent="N/A"):
    """Registra logs de segurança no Google Sheets"""
    try:
        log_id = len(get_worksheet_data('logs_seguranca')) + 1
        log_data = [
            log_id, usuario_id, acao, descricao, ip, user_agent,
            datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        ]
        return append_to_worksheet('logs_seguranca', log_data)
    except Exception as e:
        print(f"Erro ao registrar log: {e}")
        return False

# FUNÇÕES DE AUTENTICAÇÃO SEGURA ATUALIZADAS
def hash_senha(senha):
    return hashlib.sha256(senha.encode()).hexdigest()

def verificar_login(usuario_input, senha):
    """Verifica login com Google Sheets"""
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
        usuarios = get_worksheet_data('usuarios')
        senha_hash = hash_senha(senha)
        
        # Buscar usuário
        usuario_encontrado = None
        for usuario in usuarios:
            if (usuario.get('cnpj') == usuario_input or usuario.get('razao_social') == usuario_input) and \
               usuario.get('senha_hash') == senha_hash and \
               usuario.get('status') == 'Ativa':
                usuario_encontrado = usuario
                break
        
        if usuario_encontrado:
            st.session_state.login_attempts = 0  # Reseta tentativas
            registrar_log_seguranca(usuario_encontrado['id'], "LOGIN_SUCESSO", f"Usuário: {usuario_encontrado['razao_social']}")
            return usuario_encontrado
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
        usuarios = get_worksheet_data('usuarios')
        
        # Verificar se CNPJ já existe
        for usuario in usuarios:
            if usuario.get('cnpj') == cnpj:
                return False
        
        usuario_id = f"USER-{uuid.uuid4().hex[:8].upper()}"
        senha_hash = hash_senha(senha)
        
        usuario_data = [
            usuario_id, razao_social, cnpj, email, telefone, cidade, 
            senha_hash, tipo, 'Ativa', datetime.now().strftime('%d-%m-%Y %H:%M:%S')
        ]
        
        success = append_to_worksheet('usuarios', usuario_data)
        
        if success:
            registrar_log_seguranca("SISTEMA", "CADASTRO_USUARIO", f"Novo usuário: {razao_social}")
            return True
        return False
        
    except Exception as e:
        st.error(f"Erro ao cadastrar usuário: {e}")
        return False

# FUNÇÕES DO SISTEMA ATUALIZADAS
def get_estatisticas_solicitante():
    solicitacoes = get_worksheet_data('solicitacoes')
    usuarios = get_worksheet_data('usuarios')
    cotacoes = get_worksheet_data('cotacoes')
    
    hoje = datetime.now().strftime('%d-%m-%Y')
    
    solicitacoes_ativas = sum(1 for s in solicitacoes if s.get('status') == 'Aberta' and s.get('usuario_id') == 'SOL-001')
    total_transportadoras = sum(1 for u in usuarios if u.get('tipo') == 'transportadora' and u.get('status') == 'Ativa')
    
    # Total de cotações
    total_cotacoes = 0
    for cotacao in cotacoes:
        # Encontrar a solicitação correspondente
        for solicitacao in solicitacoes:
            if solicitacao.get('id') == cotacao.get('solicitacao_id') and solicitacao.get('usuario_id') == 'SOL-001':
                total_cotacoes += 1
                break
    
    # Cotações hoje
    cotacoes_hoje = 0
    for cotacao in cotacoes:
        if cotacao.get('created_at', '').startswith(hoje):
            # Verificar se a solicitação pertence ao SOL-001
            for solicitacao in solicitacoes:
                if solicitacao.get('id') == cotacao.get('solicitacao_id') and solicitacao.get('usuario_id') == 'SOL-001':
                    cotacoes_hoje += 1
                    break
    
    return {
        'solicitacoes_ativas': solicitacoes_ativas,
        'total_transportadoras': total_transportadoras,
        'total_cotacoes': total_cotacoes,
        'cotacoes_hoje': cotacoes_hoje
    }

def excluir_solicitacao(solicitacao_id):
    """Exclui uma solicitação e todas as suas cotações"""
    try:
        # Verificar se a solicitação existe
        solicitacoes = get_worksheet_data('solicitacoes')
        solicitacao_existe = any(s.get('id') == solicitacao_id for s in solicitacoes)
        
        if not solicitacao_existe:
            raise Exception("Solicitação não encontrada")
        
        # Excluir cotações relacionadas
        cotacoes = get_worksheet_data('cotacoes')
        for cotacao in cotacoes:
            if cotacao.get('solicitacao_id') == solicitacao_id:
                delete_worksheet_row('cotacoes', 'id', cotacao.get('id'))
        
        # Excluir solicitação
        success = delete_worksheet_row('solicitacoes', 'id', solicitacao_id)
        
        if success:
            registrar_log_seguranca(st.session_state.usuario_id, "EXCLUIR_SOLICITACAO", f"ID: {solicitacao_id}")
            return True
        return False
        
    except Exception as e:
        st.error(f"Erro ao excluir solicitação: {e}")
        return False

def excluir_cotacao(cotacao_id):
    """Exclui uma cotação específica do sistema"""
    try:
        # Verificar se a cotação existe
        cotacoes = get_worksheet_data('cotacoes')
        cotacao_existe = any(c.get('id') == cotacao_id for c in cotacoes)
        
        if not cotacao_existe:
            raise Exception("Cotação não encontrada")
        
        success = delete_worksheet_row('cotacoes', 'id', cotacao_id)
        
        if success:
            registrar_log_seguranca(st.session_state.usuario_id, "EXCLUIR_COTACAO", f"ID: {cotacao_id}")
            return True
        return False
        
    except Exception as e:
        st.error(f"Erro ao excluir cotação: {e}")
        return False

# FUNÇÃO DE BACKUP ATUALIZADA
def gerar_backup_excel():
    """Gera um arquivo Excel com todas as solicitações e cotações"""
    try:
        solicitacoes = get_worksheet_data('solicitacoes')
        cotacoes = get_worksheet_data('cotacoes')
        usuarios = get_worksheet_data('usuarios')
        
        dados_excel = []
        
        for sol in solicitacoes:
            if sol.get('usuario_id') == st.session_state.usuario_id:
                # Encontrar nome do usuário
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
        
        for cot in cotacoes:
            # Encontrar a solicitação correspondente
            solicitacao_encontrada = None
            for sol in solicitacoes:
                if sol.get('id') == cot.get('solicitacao_id') and sol.get('usuario_id') == st.session_state.usuario_id:
                    solicitacao_encontrada = sol
                    break
            
            if solicitacao_encontrada:
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
                    'Local Coleta': solicitacao_encontrada.get('local_coleta', ''),
                    'Local Entrega': solicitacao_encontrada.get('local_entrega', '')
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

# SISTEMA DE LOGIN SEGURO (mantido igual)
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
                        st.session_state.usuario_id = usuario['id']
                        st.session_state.razao_social = usuario['razao_social']
                        st.session_state.tipo_usuario = usuario['tipo']
                        st.success(f"Bem-vindo, {usuario['razao_social']}!")
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
                        st.success("Transportadora cadastrada com sucesso! ✅")
                        st.info("Acesso liberado imediatamente para cadastro de cotações.")
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
    usuarios = get_worksheet_data('usuarios')
    usuario_valido = None
    
    for usuario in usuarios:
        if usuario.get('id') == st.session_state.usuario_id:
            usuario_valido = usuario
            break
    
    if not usuario_valido:
        st.error("Sessão inválida. Faça login novamente.")
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()
    
    if usuario_valido.get('status') != "Ativa":
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
        
        try:
            cotacoes = get_worksheet_data('cotacoes')
            solicitacoes = get_worksheet_data('solicitacoes')
            
            ultimas_cotacoes = []
            for cot in cotacoes:
                # Encontrar solicitação correspondente
                for sol in solicitacoes:
                    if sol.get('id') == cot.get('solicitacao_id') and sol.get('usuario_id') == 'SOL-001':
                        ultimas_cotacoes.append({
                            'id': cot.get('id'),
                            'transportadora_nome': cot.get('transportadora_nome'),
                            'valor_frete': cot.get('valor_frete'),
                            'prazo_entrega': cot.get('prazo_entrega'),
                            'created_at': cot.get('created_at'),
                            'local_coleta': sol.get('local_coleta'),
                            'local_entrega': sol.get('local_entrega')
                        })
                        break
            
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
        
        cotacoes = get_worksheet_data('cotacoes')
        minhas_cotacoes = sum(1 for cot in cotacoes if cot.get('transportadora_id') == st.session_state.usuario_id)
        cotacoes_aceitas = sum(1 for cot in cotacoes if cot.get('transportadora_id') == st.session_state.usuario_id and cot.get('status') == 'Aceita')
        
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
                
                solicitacao_data = [
                    solicitacao_id, local_coleta, local_entrega, material, valor_carga,
                    data_coleta.strftime('%Y-%m-%d'), data_entrega.strftime('%Y-%m-%d'), 
                    tomador, observacoes, 'Aberta', st.session_state.usuario_id,
                    datetime.now().strftime('%d-%m-%Y %H:%M:%S')
                ]
                
                success = append_to_worksheet('solicitacoes', solicitacao_data)
                
                if success:
                    st.success(f"Solicitação {solicitacao_id} publicada com sucesso!")
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
        solicitacoes = get_worksheet_data('solicitacoes')
        minhas_solicitacoes = [s for s in solicitacoes if s.get('usuario_id') == st.session_state.usuario_id]
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
                    cotacoes = get_worksheet_data('cotacoes')
                    total_cotacoes = sum(1 for cot in cotacoes if cot.get('solicitacao_id') == sol.get('id'))
                    st.markdown(f"**Cotações recebidas:** {total_cotacoes}")
                    
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
        st.info("Nenhuma solicitação criada ainda")

# =============================================
# COTAÇÕES RECEBIDAS (COM EXCLUSÃO)
# =============================================
elif menu == "Cotações Recebidas" and st.session_state.tipo_usuario == 'solicitante':
    st.markdown("### Cotações Recebidas")
    
    try:
        cotacoes = get_worksheet_data('cotacoes')
        solicitacoes = get_worksheet_data('solicitacoes')
        
        # Filtrar cotações das minhas solicitações
        minhas_cotacoes = []
        for cot in cotacoes:
            for sol in solicitacoes:
                if sol.get('id') == cot.get('solicitacao_id') and sol.get('usuario_id') == st.session_state.usuario_id:
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
                                    update_data = [
                                        cot.get('id', ''), cot.get('solicitacao_id', ''), 
                                        cot.get('transportadora_id', ''), cot.get('transportadora_nome', ''),
                                        cot.get('valor_frete', ''), cot.get('prazo_entrega', ''),
                                        cot.get('observacoes', ''), 'Aceita', cot.get('created_at', '')
                                    ]
                                    if update_worksheet_row('cotacoes', 'id', cot.get('id', ''), update_data):
                                        st.success("Cotação aceita com sucesso!")
                                        time.sleep(1)
                                        st.rerun()
                                    else:
                                        st.error("Erro ao aceitar cotação")
                            
                            with col_recusar:
                                if st.button("Recusar", key=f"recusar_{cot.get('id', '')}_{i}", use_container_width=True):
                                    update_data = [
                                        cot.get('id', ''), cot.get('solicitacao_id', ''), 
                                        cot.get('transportadora_id', ''), cot.get('transportadora_nome', ''),
                                        cot.get('valor_frete', ''), cot.get('prazo_entrega', ''),
                                        cot.get('observacoes', ''), 'Recusada', cot.get('created_at', '')
                                    ]
                                    if update_worksheet_row('cotacoes', 'id', cot.get('id', ''), update_data):
                                        st.error("Cotação recusada!")
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
    
    usuarios = get_worksheet_data('usuarios')
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

# =============================================
# FRETES DISPONÍVEIS (PARA TRANSPORTADORAS)
# =============================================
elif menu == "Fretes Disponíveis" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### Fretes Disponíveis para Cotação")
    
    # Buscar solicitações abertas
    solicitacoes = get_worksheet_data('solicitacoes')
    solicitacoes_abertas = [s for s in solicitacoes if s.get('status') == 'Aberta']
    solicitacoes_abertas.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    if solicitacoes_abertas:
        st.info(f"**Total de fretes disponíveis:** {len(solicitacoes_abertas)}")
        
        for sol in solicitacoes_abertas:
            # Buscar cotações existentes para mostrar ranking (sem nomes)
            cotacoes = get_worksheet_data('cotacoes')
            cotacoes_existentes = [cot for cot in cotacoes if cot.get('solicitacao_id') == sol.get('id')]
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
                            cotacoes = get_worksheet_data('cotacoes')
                            ja_cotou = any(
                                cot.get('solicitacao_id') == sol.get('id') and 
                                cot.get('transportadora_id') == st.session_state.usuario_id 
                                for cot in cotacoes
                            )
                            
                            if ja_cotou:
                                st.error("Você já enviou uma cotação para este frete!")
                            else:
                                cotacao_id = f"COT-{uuid.uuid4().hex[:8].upper()}"
                                cotacao_data = [
                                    cotacao_id, sol.get('id', ''), st.session_state.usuario_id, 
                                    st.session_state.razao_social, valor_frete, prazo_entrega, 
                                    observacoes, 'Pendente', datetime.now().strftime('%d-%m-%Y %H:%M:%S')
                                ]
                                
                                if append_to_worksheet('cotacoes', cotacao_data):
                                    st.success("Cotação enviada com sucesso! Agora outras empresas verão seu valor (sem seu nome)")
                                    time.sleep(1)
                                    st.rerun()
                                else:
                                    st.error("Erro ao enviar cotação")
                        else:
                            st.error("Informe um valor válido para o frete")
    else:
        st.info("Nenhum frete disponível para cotação no momento")

# =============================================
# MINHAS COTAÇÕES (TRANSPORTADORAS)
# =============================================
elif menu == "Minhas Cotações" and st.session_state.tipo_usuario == 'transportadora':
    st.markdown("### Minhas Cotações Enviadas")
    
    cotacoes = get_worksheet_data('cotacoes')
    solicitacoes = get_worksheet_data('solicitacoes')
    
    minhas_cotacoes = []
    for cot in cotacoes:
        if cot.get('transportadora_id') == st.session_state.usuario_id:
            # Encontrar solicitação correspondente
            for sol in solicitacoes:
                if sol.get('id') == cot.get('solicitacao_id'):
                    minhas_cotacoes.append({
                        **cot,
                        'local_coleta': sol.get('local_coleta'),
                        'local_entrega': sol.get('local_entrega'),
                        'material': sol.get('material'),
                        'status_solicitacao': sol.get('status')
                    })
                    break
    
    minhas_cotacoes.sort(key=lambda x: x.get('created_at', ''), reverse=True)
    
    if minhas_cotacoes:
        st.info(f"**Total de cotações enviadas:** {len(minhas_cotacoes)}")
        
        # Estatísticas rápidas
        cotacoes_aceitas = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Aceita")
        cotacoes_pendentes = sum(1 for cot in minhas_cotacoes if cot.get('status') == "Pendente")
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Cotações Ativas", cotacoes_pendentes)
        with col2:
            st.metric("Cotações Aceitas", cotacoes_aceitas)
        with col3:
            taxa_sucesso = (cotacoes_aceitas / len(minhas_cotacoes)) * 100 if minhas_cotacoes else 0
            st.metric("Taxa de Sucesso", f"{taxa_sucesso:.1f}%")
        
        for cot in minhas_cotacoes:
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
            
            with st.expander(f"{status_color} {cot.get('id', '')} - {cot.get('local_coleta', '')} → {cot.get('local_entrega', '')} - R$ {valor_frete:,.2f}"):
                # Card com borda colorida baseada no status
                st.markdown(f"""
                <div style="border-left: {border_color}; padding-left: 1rem; margin-bottom: 1rem;">
                    <h4>{status_text}</h4>
                </div>
                """, unsafe_allow_html=True)
                
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**Material:** {cot.get('material', '')}")
                    st.markdown(f"**Meu Valor:** R$ {valor_frete:,.2f}")
                    st.markdown(f"**Meu Prazo:** {cot.get('prazo_entrega', '')}")
                    st.markdown(f"**Status da Solicitação:** {cot.get('status_solicitacao', '')}")
                
                with col2:
                    st.markdown(f"**Solicitação:** {cot.get('solicitacao_id', '')}")
                    st.markdown(f"**Data Envio:** {data_ptbr(cot.get('created_at', ''))}")
                    st.markdown(f"**Minhas Observações:** {cot.get('observacoes', '') if cot.get('observacoes') else 'Nenhuma'}")
                    
                    # Botão para cancelar cotação se ainda estiver pendente
                    if cot.get('status') == "Pendente":
                        st.markdown("---")
                        if st.button("Cancelar Cotação", key=f"cancelar_{cot.get('id', '')}"):
                            if excluir_cotacao(cot.get('id', '')):
                                st.success("Cotação cancelada com sucesso!")
                                time.sleep(1)
                                st.rerun()
                            else:
                                st.error("Erro ao cancelar cotação")
                
                # VER RANKING ATUAL DESSA SOLICITAÇÃO
                st.markdown("---")
                if st.button("Ver Ranking Atual", key=f"ranking_{cot.get('id', '')}"):
                    cotacoes_ranking = get_worksheet_data('cotacoes')
                    ranking = [c for c in cotacoes_ranking if c.get('solicitacao_id') == cot.get('solicitacao_id')]
                    ranking.sort(key=lambda x: float(x.get('valor_frete', 0)) if x.get('valor_frete') else 0)
                    
                    if ranking:
                        st.markdown("#### Ranking Atual (Menor Valor)")
                        for i, rank in enumerate(ranking[:5]):
                            posicao = i + 1
                            emoji = "🥇" if posicao == 1 else "🥈" if posicao == 2 else "🥉" if posicao == 3 else f"{posicao}º"
                            rank_valor = float(rank.get('valor_frete', 0)) if rank.get('valor_frete') else 0
                            
                            # Destacar minha cotação
                            if rank.get('id') == cot.get('id'):
                                st.markdown(f"**{emoji} R$ {rank_valor:,.2f} | {rank.get('prazo_entrega', '')} | MINHA COTAÇÃO**")
                            else:
                                st.markdown(f"{emoji} R$ {rank_valor:,.2f} | {rank.get('prazo_entrega', '')}")
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
        solicitacoes = get_worksheet_data('solicitacoes')
        cotacoes = get_worksheet_data('cotacoes')
        
        total_solicitacoes = sum(1 for s in solicitacoes if s.get('usuario_id') == st.session_state.usuario_id)
        
        # Contar cotações das minhas solicitações
        total_cotacoes = 0
        for cot in cotacoes:
            for sol in solicitacoes:
                if sol.get('id') == cot.get('solicitacao_id') and sol.get('usuario_id') == st.session_state.usuario_id:
                    total_cotacoes += 1
                    break
        
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
    
    usuarios = get_worksheet_data('usuarios')
    usuario = None
    
    for u in usuarios:
        if u.get('id') == st.session_state.usuario_id:
            usuario = u
            break
    
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
                            update_data = [
                                usuario.get('id', ''), usuario.get('razao_social', ''), 
                                usuario.get('cnpj', ''), usuario.get('email', ''),
                                usuario.get('telefone', ''), usuario.get('cidade', ''),
                                hash_senha(nova_senha), usuario.get('tipo', ''),
                                usuario.get('status', ''), usuario.get('data_cadastro', '')
                            ]
                            if update_worksheet_row('usuarios', 'id', st.session_state.usuario_id, update_data):
                                st.success("Senha atualizada com sucesso!")
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
