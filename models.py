from sqlalchemy import Column, Integer, String, DateTime, Boolean, Text
from datetime import datetime
from database import Base


class RegistroAutenticidade(Base):
    __tablename__ = "registros_autenticidade"

    id = Column(Integer, primary_key=True, index=True)
    nome_arquivo = Column(String(255), nullable=False)
    tipo_arquivo = Column(String(100), nullable=True)
    tamanho_bytes = Column(Integer, nullable=False)
    hash_sha256 = Column(String(128), unique=True, index=True, nullable=False)
    caminho_arquivo = Column(Text, nullable=False)
    selo_id = Column(String(100), unique=True, index=True, nullable=False)
    status = Column(String(50), default="autentico", nullable=False)
    criado_em = Column(DateTime, default=datetime.utcnow, nullable=False)
    usuario_id = Column(Integer, nullable=True)


class Usuario(Base):
    __tablename__ = "usuarios"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    senha_hash = Column(String(255), nullable=False)
    token = Column(String(255), unique=True, index=True, nullable=True)
    api_key = Column(String(255), unique=True, index=True, nullable=True)
    

    plano = Column(String(50), default="gratuito")
    limite_api = Column(Integer, default=10)
    uso_api = Column(Integer, default=0)

    email_confirmado = Column(Boolean, default=False)
    token_confirmacao = Column(String, nullable=True)

    criado_em = Column(DateTime, default=datetime.utcnow)

from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text

class LogRastreamento(Base):
    __tablename__ = "logs_rastreamento"

    id = Column(Integer, primary_key=True, index=True)
    selo_id = Column(String, nullable=True)
    hash_consultado = Column(String, nullable=True)
    rota = Column(String, nullable=False)
    ip_origem = Column(String, nullable=True)
    user_agent = Column(Text, nullable=True)
    resultado = Column(String, nullable=False)
    observacao = Column(Text, nullable=True)
    criado_em = Column(DateTime, default=datetime.utcnow)

class Plano(Base):
    __tablename__ = "planos"

    id = Column(Integer, primary_key=True)
    nome = Column(String(50), unique=True)
    limite_api = Column(Integer)
    ativo = Column(Boolean, default=True)