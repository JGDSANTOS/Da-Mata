import streamlit as st
import pandas as pd
from datetime import datetime
import os.path # Mantido apenas para exemplo de como era, mas não usado para credenciais

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
# Removido: from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# --- Configurações ---
# Escopos da API do Google Sheets
SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
# ID da sua planilha (Use a sua ID real)
SPREADSHEET_ID = "1Lpjc8Zb9_P8vZjt8pjjft66LpGqTE4g7uUy0hlOnUO8"
# Nome da aba onde estão os dados
SHEET_NAME = "Notas"
# Intervalo completo da aba (A1 para começar do início)
RANGE_NAME = f"{SHEET_NAME}"
# Coluna usada para filtrar por usuário
COLUNA_GESTOR_RESP = 'GESTOR_RESP'
# Coluna de assinatura
COLUNA_ASSINATURA = 'ASSINATURA'
# Coluna de data/hora da assinatura
COLUNA_GESTOR_ASSINATURA = 'GESTORASSINATURA'
# Colunas que não podem ser editadas no st.data_editor
COLUNAS_DESABILITADAS = ("NF", "FORNECEDOR", "VALOR", "DT VENC", COLUNA_GESTOR_RESP, COLUNA_GESTOR_ASSINATURA)

# --- Funções de Autenticação e API (Usando st.secrets) ---

@st.cache_resource # Cacheia o objeto 'service'
def get_sheets_service():
    """Autentica com a API do Google Sheets usando st.secrets e retorna o objeto 'service'."""
    creds = None

    # 1. Verifica se as configurações de token existem em st.secrets
    if "google_token" not in st.secrets:
        st.error("Configuração '[google_token]' não encontrada em st.secrets.")
        st.info("Por favor, gere 'token.json' localmente uma vez (usando o script antigo ou um auxiliar) "
                "e copie seu conteúdo, junto com 'credentials.json', para '.streamlit/secrets.toml'.")
        return None

    try:
        # Carrega as informações do token do st.secrets
        token_info = st.secrets["google_token"].to_dict()
        creds = Credentials.from_authorized_user_info(token_info, SCOPES)

    except Exception as e:
        st.error(f"Erro ao carregar credenciais de 'st.secrets[google_token]': {e}")
        st.info("Verifique se a estrutura de [google_token] em secrets.toml está correta.")
        return None

    # 2. Verifica se as credenciais são válidas ou podem ser atualizadas
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            st.info("Token expirado. Tentando atualizar...")
            try:
                creds.refresh(Request())
                st.success("Token atualizado com sucesso!")
                # NOTA: O token atualizado fica em memória. Não tentamos reescrever no secrets.
            except Exception as e:
                st.error(f"Erro ao atualizar o token de acesso: {e}")
                st.warning("Pode ser necessário re-autenticar localmente e atualizar "
                           "o 'token.json' / 'secrets.toml'.")
                return None
        else:
            st.error("Credenciais inválidas ou ausentes e não foi possível atualizar.")
            st.info("Verifique se 'token.json' foi gerado corretamente e copiado "
                    "para '[google_token]' em 'secrets.toml'.")
            return None

    # 3. Constrói e retorna o serviço da API
    try:
        service = build("sheets", "v4", credentials=creds)
        return service
    except HttpError as err:
        st.error(f"Erro ao construir o serviço do Google Sheets: {err}")
        return None
    except Exception as e:
        st.error(f"Um erro inesperado ocorreu ao construir o serviço: {e}")
        return None

# --- Funções de Manipulação de Dados ---

@st.cache_data(ttl=600) # Cacheia os dados por 10 minutos
def get_tabela_sheets(_service):
    """Busca os dados da planilha e retorna um DataFrame Pandas."""
    if not _service:
        st.error("Serviço do Google Sheets não está disponível.")
        return None

    try:
        sheet = _service.spreadsheets()
        result = (
            sheet.values()
            .get(spreadsheetId=SPREADSHEET_ID, range=SHEET_NAME)
            .execute()
        )
        values = result.get("values", [])

        if not values:
            st.warning(f"Nenhum dado encontrado na planilha '{SHEET_NAME}'.")
            return None
        else:
            header = values[0]
            data = values[1:]
            df = pd.DataFrame(data, columns=header)
            
            # --- Conversão de Tipos ---
            if COLUNA_ASSINATURA in df.columns:
                df[COLUNA_ASSINATURA] = df[COLUNA_ASSINATURA].astype(str).str.upper()
                df[COLUNA_ASSINATURA] = df[COLUNA_ASSINATURA].map({'TRUE': True, 'VERDADEIRO': True}).fillna(False).astype(bool)
            else:
                st.error(f"Coluna '{COLUNA_ASSINATURA}' não encontrada!")
                return None

            if COLUNA_GESTOR_ASSINATURA not in df.columns:
                 df[COLUNA_GESTOR_ASSINATURA] = ''

            if 'VALOR' in df.columns:
                 df['VALOR'] = pd.to_numeric(df['VALOR'].str.replace(',', '.', regex=False), errors='coerce').fillna(0)
            if 'DT VENC' in df.columns:
                df['DT VENC'] = pd.to_datetime(df['DT VENC'], errors='coerce', dayfirst=True)

            return df

    except HttpError as err:
        st.error(f"Erro na API do Google Sheets ao buscar dados: {err}")
        if err.resp.status == 403:
            st.warning("Erro de permissão. Tentando limpar cache de autenticação...")
            get_sheets_service.clear()
        return None
    except Exception as e:
        st.error(f"Erro inesperado ao buscar dados: {e}")
        return None

def update_tabela_sheets(_service, df_atualizado):
    """Atualiza os dados na planilha do Google Sheets."""
    if not _service:
        st.error("Serviço do Google Sheets não está disponível para atualização.")
        return False

    try:
        sheet = _service.spreadsheets()

        df_to_save = df_atualizado.copy()
        if COLUNA_ASSINATURA in df_to_save.columns:
             df_to_save[COLUNA_ASSINATURA] = df_to_save[COLUNA_ASSINATURA].apply(lambda x: 'TRUE' if x else 'FALSE')
        if 'DT VENC' in df_to_save.columns:
             df_to_save['DT VENC'] = df_to_save['DT VENC'].dt.strftime('%d/%m/%Y').fillna('')

        df_to_save = df_to_save.astype(str).replace({'NaT': '', 'nan': ''})
        data_to_write = [df_to_save.columns.tolist()] + df_to_save.values.tolist()
        body = {"values": data_to_write}

        result = (
            sheet.values()
            .update(
                spreadsheetId=SPREADSHEET_ID,
                range=RANGE_NAME,
                valueInputOption="USER_ENTERED",
                body=body,
            )
            .execute()
        )
        st.info(f"{result.get('updatedCells')} células atualizadas.")
        return True

    except HttpError as error:
        st.error(f"Ocorreu um erro ao atualizar a planilha: {error}")
        return False
    except Exception as e:
        st.error(f"Um erro inesperado ocorreu durante a atualização: {e}")
        return False

# --- Funções de Autenticação do Usuário ---

def check_password():
    """Verifica a senha usando st.secrets."""
    
    if "users" not in st.secrets:
        st.error("A configuração de 'users' não foi encontrada em st.secrets.")
        st.info("Certifique-se de criar um arquivo 'secrets.toml' no diretório '.streamlit' com o formato:\n\n[users]\nusername1 = \"password123\"")
        return False

    def password_entered():
        user = st.session_state.get("username")
        pwd = st.session_state.get("password")
        
        users_dict = st.secrets["users"].to_dict() # Converte para dict
        
        if user and pwd and user in users_dict and pwd == users_dict[user]:
            st.session_state["password_correct"] = True
            st.session_state["logged_in_user"] = user
            del st.session_state["password"]
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state:
        st.session_state["password_correct"] = False

    if not st.session_state["password_correct"]:
        st.title("Login :closed_lock_with_key:")
        usernames = list(st.secrets["users"].keys())
        st.selectbox("Selecione seu nome de usuário:", usernames, key="username")
        st.text_input("Senha:", type="password", on_change=password_entered, key="password")

        if "password" in st.session_state and st.session_state["password"] and not st.session_state["password_correct"]:
            st.error("Usuário ou senha incorretos.")
        return False
    
    return True

# --- Lógica Principal do Aplicativo ---

def main():
    """Função principal que executa o aplicativo Streamlit."""
    
    st.set_page_config(page_title="Controle de Notas", layout="wide")

    if not check_password():
        st.stop()

    service = get_sheets_service()
    if not service:
        st.stop()

    st.title("CONTROLE DE NOTAS :lower_left_fountain_pen:")
    logged_in_user = st.session_state.get("logged_in_user", "Usuário Desconhecido")
    st.sidebar.success(f"Bem-vindo(a), {logged_in_user}!")

    if st.sidebar.button("🔄 Recarregar Dados"):
        get_tabela_sheets.clear()
        st.rerun()
        
    if st.sidebar.button("🚪 Sair"):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

    df_original = get_tabela_sheets(service)

    if df_original is None:
        st.error("Não foi possível carregar os dados. Verifique a planilha e as mensagens de erro acima.")
        st.stop()
        
    if COLUNA_GESTOR_RESP in df_original.columns:
        df_filtrado = df_original[df_original[COLUNA_GESTOR_RESP] == logged_in_user].copy()
        
        if df_filtrado.empty:
            st.info(f"Nenhum registro encontrado para o gestor {logged_in_user}.")
            st.stop()

        st.subheader(f"Suas Notas Pendentes ({logged_in_user})")

        edited_df = st.data_editor(
            df_filtrado,
            disabled=COLUNAS_DESABILITADAS,
            key=f"editor_{logged_in_user}",
            use_container_width=True,
            column_config={
                COLUNA_ASSINATURA: st.column_config.CheckboxColumn(
                    "Assinar?",
                    default=False,
                ),
                "VALOR": st.column_config.NumberColumn(
                    "Valor (R$)",
                    format="%.2f",
                ),
                "DT VENC": st.column_config.DateColumn(
                     "Vencimento",
                     format="DD/MM/YYYY",
                )
            }
        )

        if st.button("Salvar Alterações", type="primary"):
            try:
                indices_editados = edited_df.index
                mudancas = edited_df[COLUNA_ASSINATURA] & ~df_filtrado.loc[indices_editados, COLUNA_ASSINATURA]
                now_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                edited_df.loc[mudancas, COLUNA_GESTOR_ASSINATURA] = now_str
                
                df_original.update(edited_df)

                if update_tabela_sheets(service, df_original):
                    st.success("As alterações foram salvas com sucesso!")
                    st.balloons()
                    get_tabela_sheets.clear()
                    st.rerun()
                else:
                    st.error("Falha ao salvar as alterações no Google Sheets.")

            except Exception as e:
                st.error(f"Ocorreu um erro ao processar ou salvar as alterações: {e}")

    else:
        st.error(f"Coluna '{COLUNA_GESTOR_RESP}' não encontrada na planilha.")

# --- Ponto de Entrada ---
if __name__ == "__main__":
    main()