import base64
import hashlib
import hmac
import json
import os
import uuid
import bcrypt
from datetime import datetime
from pathlib import Path

import qrcode
from PIL import Image


UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)

DNA_MARKER = "|DNA_ORACULO_FIM|"
DNA_SECRET = os.getenv("DNA_ORACULO_SECRET")

if not DNA_SECRET:
    raise Exception("DNA_ORACULO_SECRET não configurado!")


def gerar_hash_arquivo(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for bloco in iter(lambda: f.read(4096), b""):
            sha256.update(bloco)
    return sha256.hexdigest()


def gerar_selo_id() -> str:
    return f"ORACULO-{uuid.uuid4().hex[:16].upper()}"


def salvar_arquivo_upload(file, nome_original: str) -> str:
    extensao = Path(nome_original).suffix or ".bin"
    nome_unico = f"{uuid.uuid4().hex}{extensao}"
    caminho = UPLOAD_DIR / nome_unico

    with open(caminho, "wb") as buffer:
        buffer.write(file.file.read())

    return str(caminho)


def tamanho_arquivo(file_path: str) -> int:
    return os.path.getsize(file_path)


def gerar_qrcode(texto: str, caminho: str):
    img = qrcode.make(texto)
    img.save(caminho)


def gerar_hash_senha(senha: str) -> str:
    hash_bytes = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
    return hash_bytes.decode()

def verificar_senha(senha: str, hash_salvo: str) -> bool:
    return bcrypt.checkpw(senha.encode(), hash_salvo.encode())


def gerar_token() -> str:
    return uuid.uuid4().hex + uuid.uuid4().hex


def gerar_api_key() -> str:
    return "ORACULO-" + uuid.uuid4().hex


def arquivo_eh_imagem(nome_arquivo: str) -> bool:
    ext = Path(nome_arquivo).suffix.lower()
    return ext in {".png", ".jpg", ".jpeg", ".webp", ".bmp", ".tiff"}


# =========================
# DNA ENGINE BASE
# =========================

def _assinar_payload_dna(payload_sem_assinatura: dict) -> str:
    payload_ordenado = json.dumps(
        payload_sem_assinatura,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )
    assinatura = hmac.new(
        DNA_SECRET.encode(),
        payload_ordenado.encode(),
        hashlib.sha256
    ).hexdigest()
    return assinatura


def gerar_dna_payload(
    selo_id: str,
    hash_sha256: str,
    usuario_id: int | None,
    tipo_arquivo: str,
    nome_arquivo: str
) -> dict:
    payload = {
        "versao": "DNA_ORACULO_V1",
        "selo_id": selo_id,
        "hash_prefix": hash_sha256[:24],
        "usuario_id": usuario_id,
        "tipo_arquivo": tipo_arquivo or "desconhecido",
        "nome_arquivo": nome_arquivo,
        "timestamp_utc": datetime.utcnow().isoformat()
    }
    payload["assinatura"] = _assinar_payload_dna(payload)
    return payload


def gerar_dna_token(
    selo_id: str,
    hash_sha256: str,
    usuario_id: int | None,
    tipo_arquivo: str,
    nome_arquivo: str
) -> str:
    payload = gerar_dna_payload(
        selo_id=selo_id,
        hash_sha256=hash_sha256,
        usuario_id=usuario_id,
        tipo_arquivo=tipo_arquivo,
        nome_arquivo=nome_arquivo
    )

    payload_json = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    )

    token = base64.urlsafe_b64encode(payload_json.encode()).decode()
    return token


def validar_dna_token(dna_token: str) -> dict | None:
    try:
        payload_json = base64.urlsafe_b64decode(dna_token.encode()).decode()
        payload = json.loads(payload_json)

        assinatura_recebida = payload.pop("assinatura", None)
        if not assinatura_recebida:
            return None

        assinatura_esperada = _assinar_payload_dna(payload)
        if not hmac.compare_digest(assinatura_recebida, assinatura_esperada):
            return None

        payload["assinatura"] = assinatura_recebida
        return payload

    except Exception:
        return None


def gerar_arquivo_dna_path(selo_id: str) -> str:
    return str(UPLOAD_DIR / f"{selo_id}_dna.png")


def _texto_para_bits(texto: str) -> str:
    texto_final = texto + DNA_MARKER
    return "".join(format(ord(char), "08b") for char in texto_final)


def inserir_dna_imagem(caminho_original: str, caminho_saida: str, dna_texto: str) -> str:
    img = Image.open(caminho_original).convert("RGB")
    bits = _texto_para_bits(dna_texto)

    largura, altura = img.size
    capacidade = largura * altura * 3

    if len(bits) > capacidade:
        raise ValueError("Imagem pequena demais para receber o DNA Oráculo.")

    pixels = list(img.getdata())
    novos_pixels = []
    bit_index = 0

    for r, g, b in pixels:
        canais = [r, g, b]

        for i in range(3):
            if bit_index < len(bits):
                canais[i] = (canais[i] & ~1) | int(bits[bit_index])
                bit_index += 1

        novos_pixels.append(tuple(canais))

    img_dna = Image.new("RGB", img.size)
    img_dna.putdata(novos_pixels)
    img_dna.save(caminho_saida, format="PNG")

    return caminho_saida


def extrair_dna_imagem(caminho_arquivo: str) -> str | None:
    img = Image.open(caminho_arquivo).convert("RGB")
    bits = []

    for r, g, b in img.getdata():
        bits.append(str(r & 1))
        bits.append(str(g & 1))
        bits.append(str(b & 1))

    chars = []

    for i in range(0, len(bits), 8):
        byte = bits[i:i + 8]
        if len(byte) < 8:
            break

        chars.append(chr(int("".join(byte), 2)))
        texto_atual = "".join(chars)

        if texto_atual.endswith(DNA_MARKER):
            return texto_atual.replace(DNA_MARKER, "")

    return None

from pypdf import PdfReader, PdfWriter


# =========================
# DNA PARA PDF
# =========================

def inserir_dna_pdf(caminho_original: str, caminho_saida: str, dna_token: str) -> str:
    reader = PdfReader(caminho_original)
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    metadata = reader.metadata or {}
    metadata_atualizada = dict(metadata)
    metadata_atualizada["/DNA_ORACULO"] = dna_token

    writer.add_metadata(metadata_atualizada)

    with open(caminho_saida, "wb") as f:
        writer.write(f)

    return caminho_saida


def extrair_dna_pdf(caminho_pdf: str) -> str | None:
    reader = PdfReader(caminho_pdf)

    metadata = reader.metadata
    if not metadata:
        return None

    return metadata.get("/DNA_ORACULO")

from docx import Document


# =========================
# DNA PARA DOCX
# =========================

def inserir_dna_docx(caminho_original: str, caminho_saida: str, dna_token: str) -> str:
    payload = validar_dna_token(dna_token)
    if not payload:
        raise ValueError("DNA token inválido para DOCX.")

    selo_id = str(payload.get("selo_id", ""))
    hash_prefix = str(payload.get("hash_prefix", ""))
    usuario_id = str(payload.get("usuario_id", ""))
    assinatura_curta = str(payload.get("assinatura", ""))[:16]

    dna_curto = f"DNAO|{selo_id}|{hash_prefix}|{usuario_id}|{assinatura_curta}"

    if len(dna_curto) > 255:
        raise ValueError(f"DNA curto ainda excede 255 chars: {len(dna_curto)}")

    doc = Document(caminho_original)
    props = doc.core_properties
    props.comments = dna_curto
    doc.save(caminho_saida)
    return caminho_saida


def extrair_dna_docx(caminho_docx: str) -> dict | None:
    doc = Document(caminho_docx)
    props = doc.core_properties
    comentarios = props.comments or ""

    if not comentarios.startswith("DNAO|"):
        return None

    partes = comentarios.split("|")
    if len(partes) != 5:
        return None

    _, selo_id, hash_prefix, usuario_id, assinatura_curta = partes

    return {
        "selo_id": selo_id,
        "hash_prefix": hash_prefix,
        "usuario_id": usuario_id,
        "assinatura_curta": assinatura_curta
    }