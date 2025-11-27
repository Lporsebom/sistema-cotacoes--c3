import streamlit as st
import pandas as pd
import yfinance as yf
import plotly.graph_objects as go
from datetime import datetime, timedelta
import requests

# Configuração da página
st.set_page_config(
    page_title="Sistema de Cotações",
    page_icon="📈",
    layout="wide"
)

# Título do aplicativo
st.title("📈 Sistema de Cotações - C3")
st.markdown("---")

# Sidebar para configurações
st.sidebar.header("Configurações")

# Seleção de ativos
ativos = st.sidebar.multiselect(
    "Selecione os ativos:",
    ["PETR4.SA", "VALE3.SA", "ITUB4.SA", "BBDC4.SA", "WEGE3.SA", "MGLU3.SA", "BBAS3.SA", "ABEV3.SA"],
    default=["PETR4.SA", "VALE3.SA"]
)

# Período de análise
periodo = st.sidebar.selectbox(
    "Período:",
    ["1d", "5d", "1mo", "3mo", "6mo", "1y", "2y"],
    index=2
)

# Layout principal
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("Gráfico de Preços")
    
    if ativos:
        # Baixar dados
        try:
            dados = yf.download(ativos, period=periodo)['Close']
            
            # Plotar gráfico
            fig = go.Figure()
            
            for ativo in ativos:
                fig.add_trace(go.Scatter(
                    x=dados.index,
                    y=dados[ativo],
                    name=ativo,
                    line=dict(width=2)
                ))
            
            fig.update_layout(
                title="Evolução dos Preços",
                xaxis_title="Data",
                yaxis_title="Preço (R$)",
                height=500,
                showlegend=True
            )
            
            st.plotly_chart(fig, use_container_width=True)
            
        except Exception as e:
            st.error(f"Erro ao baixar dados: {e}")
    else:
        st.warning("Selecione pelo menos um ativo para visualizar o gráfico.")

with col2:
    st.subheader("Cotações Atuais")
    
    if ativos:
        try:
            # Criar tabela de cotações atuais
            cotacoes_data = []
            
            for ativo in ativos:
                ticker = yf.Ticker(ativo)
                info = ticker.info
                hist = ticker.history(period="1d")
                
                if not hist.empty:
                    preco_atual = hist['Close'].iloc[-1]
                    variacao = ((preco_atual - hist['Open'].iloc[-1]) / hist['Open'].iloc[-1]) * 100
                    
                    cotacoes_data.append({
                        "Ativo": ativo,
                        "Preço (R$)": f"R$ {preco_atual:.2f}",
                        "Variação (%)": f"{variacao:+.2f}%",
                        "Cor": "🟢" if variacao >= 0 else "🔴"
                    })
            
            df_cotacoes = pd.DataFrame(cotacoes_data)
            st.dataframe(df_cotacoes, use_container_width=True)
            
        except Exception as e:
            st.error(f"Erro ao obter cotações atuais: {e}")

# Seção de detalhes
if ativos:
    st.markdown("---")
    st.subheader("Detalhes dos Ativos")
    
    for ativo in ativos:
        with st.expander(f"📊 Detalhes - {ativo}"):
            try:
                ticker = yf.Ticker(ativo)
                info = ticker.info
                
                col_info1, col_info2, col_info3 = st.columns(3)
                
                with col_info1:
                    st.metric("Preço Atual", f"R$ {info.get('currentPrice', 'N/A')}")
                    st.metric("Mínima do Dia", f"R$ {info.get('dayLow', 'N/A')}")
                    st.metric("Máxima do Dia", f"R$ {info.get('dayHigh', 'N/A')}")
                
                with col_info2:
                    st.metric("Valor de Mercado", f"R$ {info.get('marketCap', 'N/A')}")
                    st.metric("Volume", f"{info.get('volume', 'N/A'):,}")
                    st.metric("P/L", f"{info.get('trailingPE', 'N/A')}")
                
                with col_info3:
                    st.metric("Dividend Yield", f"{info.get('dividendYield', 0)*100 if info.get('dividendYield') else 'N/A'}%")
                    st.metric("ROE", f"{info.get('returnOnEquity', 'N/A')}")
                    st.metric("Setor", info.get('sector', 'N/A'))
                    
            except Exception as e:
                st.error(f"Erro ao obter detalhes de {ativo}: {e}")

# Rodapé
st.markdown("---")
st.markdown(
    "**Sistema de Cotações C3** - Desenvolvido com Streamlit | "
    "Dados fornecidos por Yahoo Finance"
)