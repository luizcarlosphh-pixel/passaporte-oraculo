from pydantic import BaseModel
from datetime import datetime


class RegistroResponse(BaseModel):
    id: int
    nome_arquivo: str
    tipo_arquivo: str | None
    tamanho_bytes: int
    hash_sha256: str
    selo_id: str
    status: str
    criado_em: datetime

    class Config:
        from_attributes = True


class ValidacaoResponse(BaseModel):
    encontrado: bool
    autentico: bool
    mensagem: str
    registro: RegistroResponse | None = None