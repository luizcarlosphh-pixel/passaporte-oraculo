from services import inserir_dna_pdf, extrair_dna_pdf
from services import verificar_senha
from pathlib import Path
from io import BytesIO
import tempfile
import shutil
import os
import smtplib
import secrets
import requests



from email.mime.text import MIMEText
from email_validator import validate_email, EmailNotValidError
from fastapi import FastAPI, UploadFile, File, Depends, HTTPException, Header, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from sqlalchemy.orm import Session
from fastapi import Query

from reportlab.lib.pagesizes import A4
from reportlab.lib.colors import HexColor, white
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from database import Base, engine, get_db
from models import RegistroAutenticidade, Usuario, LogRastreamento, Plano
from services import (
    salvar_arquivo_upload,
    gerar_hash_arquivo,
    gerar_selo_id,
    tamanho_arquivo,
    gerar_qrcode,
    gerar_hash_senha,
    gerar_token,
    gerar_api_key,
    arquivo_eh_imagem,
    gerar_dna_token,
    validar_dna_token,
    gerar_arquivo_dna_path,
    inserir_dna_imagem,
    extrair_dna_imagem,
    inserir_dna_docx,
    extrair_dna_docx
)

Base.metadata.create_all(bind=engine)

def criar_planos_padrao():
    db = Session(bind=engine)
    try:
        planos = [
            {"nome": "free", "limite_api": 10},
            {"nome": "pro", "limite_api": 1000},
            {"nome": "enterprise", "limite_api": 999999},
        ]

        for p in planos:
            existe = db.query(Plano).filter(Plano.nome == p["nome"]).first()
            if not existe:
                db.add(Plano(nome=p["nome"], limite_api=p["limite_api"], ativo=True))

        db.commit()
    finally:
        db.close()

criar_planos_padrao()

app = FastAPI(
    title="Passaporte Oráculo",
    description="Protocolo de autenticidade digital contra deepfakes e manipulações.",
    version="1.0.0"
)

BASE_DIR = Path(__file__).resolve().parent
INDEX_FILE = BASE_DIR / "static" / "index.html"
APP_BASE_URL = os.getenv("APP_BASE_URL", "http://127.0.0.1:8000")
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN")


def obter_usuario_por_token(authorization: str | None, db: Session) -> Usuario:
    if not authorization:
        raise HTTPException(status_code=401, detail="Token não enviado.")

    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Formato de token inválido.")

    token = authorization.replace("Bearer ", "").strip()
    usuario = db.query(Usuario).filter(Usuario.token == token).first()

    if not usuario:
        raise HTTPException(status_code=401, detail="Token inválido ou expirado.")

    return usuario


def obter_usuario_por_api_key(x_api_key: str | None, db: Session) -> Usuario:
    if not x_api_key:
        raise HTTPException(status_code=401, detail="API Key não enviada.")

    usuario = db.query(Usuario).filter(Usuario.api_key == x_api_key).first()

    if not usuario:
        raise HTTPException(status_code=401, detail="API Key inválida.")

    return usuario

def enviar_email_confirmacao(destino: str, link_confirmacao: str):
    RESEND_API_KEY = os.getenv("RESEND_API_KEY")

    if not RESEND_API_KEY:
        raise Exception("RESEND_API_KEY não configurada!")

    response = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json",
        },
        json={
            "from": "onboarding@resend.dev",
            "to": destino,
            "subject": "Confirme seu email - Passaporte Oráculo",
            "html": f"""
                <h2>Confirme sua conta</h2>
                <p>Clique no botão abaixo:</p>
                <a href="{link_confirmacao}" style="padding:10px;background:#000;color:#fff;text-decoration:none;">
                    Confirmar Email
                </a>
            """,
        },
    )

    if response.status_code != 200:
        raise Exception(f"Erro ao enviar email: {response.text}")

    print("EMAIL ENVIADO COM RESEND:", destino)

def registrar_log_rastreamento(
    db: Session,
    request: Request,
    rota: str,
    resultado: str,
    selo_id: str | None = None,
    hash_consultado: str | None = None,
    observacao: str | None = None
):
    ip_origem = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    log = LogRastreamento(
        selo_id=selo_id,
        hash_consultado=hash_consultado,
        rota=rota,
        ip_origem=ip_origem,
        user_agent=user_agent,
        resultado=resultado,
        observacao=observacao
    )

    db.add(log)
    db.commit()


def enviar_alerta_email(destino: str, assunto: str, mensagem: str):
    try:
        EMAIL_USER = os.getenv("EMAIL_USER")
        EMAIL_PASS = os.getenv("EMAIL_PASS")

        if not EMAIL_USER or not EMAIL_PASS:
            raise Exception("EMAIL_USER ou EMAIL_PASS não configurados.")

        msg = MIMEText(mensagem)
        msg["Subject"] = assunto
        msg["From"] = EMAIL_USER
        msg["To"] = destino

        servidor = smtplib.SMTP("smtp.gmail.com", 587)
        servidor.starttls()
        servidor.login(EMAIL_USER, EMAIL_PASS)
        servidor.send_message(msg)
        servidor.quit()

        print("ALERTA EMAIL ENVIADO COM SUCESSO")
    except Exception as e:
        print("ERRO AO ENVIAR EMAIL:", str(e))

    
def localizar_registro_por_dna(dna_texto: str, db: Session):
    try:
        payload = validar_dna_token(dna_texto)
        if not payload:
            return None

        selo_id = payload.get("selo_id")
        hash_prefix = payload.get("hash_prefix")
        usuario_id = payload.get("usuario_id")

        registro = db.query(RegistroAutenticidade).filter(
            RegistroAutenticidade.selo_id == selo_id
        ).first()

        if not registro:
            return None

        if not registro.hash_sha256.startswith(hash_prefix):
            return None

        if str(registro.usuario_id) != str(usuario_id):
            return None

        return registro

    except Exception:
        return None


def gerar_certidao_pdf(registro: RegistroAutenticidade, email_usuario: str | None = None) -> BytesIO:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)

    largura, altura = A4

    cor_fundo = HexColor("#0b1220")
    cor_card = HexColor("#111827")
    cor_azul = HexColor("#00d4ff")
    cor_texto = white
    cor_texto_sec = HexColor("#cbd5e1")
    cor_verde = HexColor("#4ade80")

    pdf.setFillColor(cor_fundo)
    pdf.rect(0, 0, largura, altura, fill=1, stroke=0)

    margem = 40
    pdf.setFillColor(cor_card)
    pdf.roundRect(margem, 70, largura - 80, altura - 120, 18, fill=1, stroke=0)

    pdf.setFillColor(cor_azul)
    pdf.setFont("Helvetica-Bold", 24)
    pdf.drawString(60, altura - 70, "Passaporte Oraculo")

    pdf.setFillColor(cor_texto_sec)
    pdf.setFont("Helvetica", 11)
    pdf.drawString(60, altura - 90, "Certidao de Autenticidade Digital")
    pdf.drawString(60, altura - 106, "Documento de prova de registro e integridade do conteudo")

    pdf.setFillColor(cor_verde)
    pdf.setFont("Helvetica-Bold", 14)
    pdf.drawString(60, altura - 140, "STATUS: AUTENTICO")

    y = altura - 180
    espacamento = 34

    possui_dna = (BASE_DIR / "uploads" / f"{registro.selo_id}_dna.png").exists()

    dados = [
        ("Numero da certidao", registro.selo_id),
        ("Arquivo", registro.nome_arquivo),
        ("Hash SHA-256", registro.hash_sha256),
        ("Data da selagem", str(registro.criado_em)),
        ("Status", registro.status),
        ("Usuario responsavel", email_usuario or f"usuario_id={registro.usuario_id}"),
        ("DNA Oraculo", "Ativo para imagem" if possui_dna else "Nao aplicado"),
        ("Link de validacao", f"http://127.0.0.1:8000/verificar/{registro.selo_id}")
    ]

    for rotulo, valor in dados:
        pdf.setFillColor(cor_azul)
        pdf.setFont("Helvetica-Bold", 11)
        pdf.drawString(60, y, rotulo)

        pdf.setFillColor(cor_texto)
        pdf.setFont("Helvetica", 10)

        texto = str(valor)
        linhas = []
        while len(texto) > 85:
            corte = texto[:85]
            ultimo_espaco = corte.rfind(" ")
            if ultimo_espaco == -1:
                ultimo_espaco = 85
            linhas.append(texto[:ultimo_espaco])
            texto = texto[ultimo_espaco:].lstrip()
        linhas.append(texto)

        y_texto = y - 14
        for linha in linhas:
            pdf.drawString(60, y_texto, linha)
            y_texto -= 12

        y -= max(espacamento, 28 + (len(linhas) - 1) * 12)

    pdf.setFillColor(cor_texto_sec)
    pdf.setFont("Helvetica", 10)
    texto_formal = [
        "Declaramos que o arquivo identificado neste documento foi registrado no sistema",
        "Passaporte Oraculo, recebendo identificador criptografico unico e selo exclusivo",
        "de autenticidade. Este documento serve como evidencia complementar de integridade,",
        "rastreabilidade e registro digital do conteudo no momento da selagem."
    ]

    y_formal = 185
    for linha in texto_formal:
        pdf.drawString(60, y_formal, linha)
        y_formal -= 13

    caminho_qr = BASE_DIR / "uploads" / f"{registro.selo_id}.png"
    if caminho_qr.exists():
        img = ImageReader(str(caminho_qr))
        pdf.drawImage(img, largura - 210, 120, width=120, height=120, mask="auto")

    pdf.setFillColor(cor_texto_sec)
    pdf.setFont("Helvetica", 9)
    pdf.drawString(largura - 220, 105, "Escaneie para validar a autenticidade")

    pdf.setStrokeColor(HexColor("#24324d"))
    pdf.line(60, 55, largura - 60, 55)

    pdf.setFillColor(cor_texto_sec)
    pdf.setFont("Helvetica", 8)
    pdf.drawString(60, 40, "Passaporte Oraculo - Documento gerado automaticamente")
    pdf.drawRightString(largura - 60, 40, f"Selo: {registro.selo_id}")

    pdf.showPage()
    pdf.save()

    buffer.seek(0)
    return buffer


@app.get("/")
def home():
    if not INDEX_FILE.exists():
        raise HTTPException(status_code=500, detail=f"Arquivo não encontrado: {INDEX_FILE}")
    return FileResponse(INDEX_FILE)


@app.get("/admin-dados")
def admin_panel(
    admin_token: str = Query(...),
    db: Session = Depends(get_db)
):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Acesso negado.")

    usuarios = db.query(Usuario).all()
    registros = db.query(RegistroAutenticidade).all()

    total_usuarios = len(usuarios)
    total_registros = len(registros)

    return {
        "total_usuarios": total_usuarios,
        "total_registros": total_registros,
        "usuarios": [
            {
                "id": u.id,
                "email": u.email,
                "uso_api": u.uso_api,
                "limite_api": u.limite_api,
                "percentual_uso": (u.uso_api / u.limite_api) * 100 if u.limite_api > 0 else 0,
                "status": (
                    "sem_credito" if u.limite_api == 0 else
                    "quase_no_limite" if u.uso_api >= u.limite_api * 0.8 else
                    "normal"
                )
            }
            for u in usuarios
        ]
    }

@app.get("/admin-ui")
def admin_ui(admin_token: str = Query(...)):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Acesso negado.")

    return FileResponse("static/admin.html")

@app.get("/landing")
def landing():
    landing_file = BASE_DIR / "static" / "landing.html"

    if not landing_file.exists():
        raise HTTPException(status_code=500, detail=f"Arquivo não encontrado: {landing_file}")

    return FileResponse(landing_file)

@app.post("/registrar")
def registrar_usuario(email: str, senha: str, db: Session = Depends(get_db)):
    try:
        email_validado = validate_email(email)
        email_limpo = email_validado.email
    except EmailNotValidError as e:
        raise HTTPException(status_code=400, detail=f"Email inválido: {str(e)}")

    usuario_existente = db.query(Usuario).filter(Usuario.email == email_limpo).first()
    if usuario_existente:
        raise HTTPException(status_code=400, detail="Email já cadastrado.")

    token_confirmacao = secrets.token_hex(24)

    plano_free = db.query(Plano).filter(Plano.nome == "free").first()

    novo_usuario = Usuario(
        email=email_limpo,
        senha_hash=gerar_hash_senha(senha),
        plano="free",
        limite_api=plano_free.limite_api if plano_free else 10,
        uso_api=0,
        email_confirmado=False,
        token_confirmacao=token_confirmacao
    )

    db.add(novo_usuario)
    db.commit()
    db.refresh(novo_usuario)

    link_confirmacao = f"{APP_BASE_URL}/confirmar-email/{token_confirmacao}"
    enviar_email_confirmacao(email_limpo, link_confirmacao)

    return {
        "mensagem": "Cadastro realizado com sucesso. Confirme seu email para ativar a conta.",
        "email": novo_usuario.email
    }

@app.post("/reenviar-confirmacao")
def reenviar_confirmacao(email: str, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if usuario.email_confirmado:
        return {"mensagem": "Este email já foi confirmado."}

    if not usuario.token_confirmacao:
        usuario.token_confirmacao = secrets.token_hex(24)
        db.commit()
        db.refresh(usuario)

    link_confirmacao = f"{APP_BASE_URL}/confirmar-email/{usuario.token_confirmacao}"
    enviar_email_confirmacao(usuario.email, link_confirmacao)

    return {"mensagem": "Email de confirmação reenviado com sucesso."}

@app.post("/login")
def login_usuario(email: str, senha: str, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.email == email).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    if not verificar_senha(senha, usuario.senha_hash):
        raise HTTPException(status_code=401, detail="Senha incorreta.")

    if not usuario.email_confirmado:
        raise HTTPException(status_code=403, detail="Confirme seu email antes de entrar.")

    usuario.token = gerar_token()

    if not usuario.api_key:
        usuario.api_key = gerar_api_key()

    db.commit()
    db.refresh(usuario)

    return {
        "mensagem": "Login realizado com sucesso",
        "usuario_id": usuario.id,
        "email": usuario.email,
        "token": usuario.token,
        "api_key": usuario.api_key
    }


@app.get("/confirmar-email/{token}")
def confirmar_email(token: str, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.token_confirmacao == token).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Token de confirmação inválido.")

    usuario.email_confirmado = True
    usuario.token_confirmacao = None
    db.commit()

    return HTMLResponse("""
    <html>
        <body style="background:#0a0f1f;color:white;text-align:center;margin-top:100px;font-family:Arial;">
            <h1 style="color:#4ade80;">✅ Email confirmado</h1>
            <p>Sua conta foi ativada com sucesso.</p>
            <a href="/" style="color:#38bdf8;">Ir para o sistema</a>
        </body>
    </html>
    """)

@app.post("/selar")
def selar_arquivo(
    arquivo: UploadFile = File(...),
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    try:
        usuario = obter_usuario_por_token(authorization, db)
        # 🚫 BLOQUEIO POR LIMITE
        if usuario.uso_api >= usuario.limite_api:
            return {
                "erro": "limite_excedido",
                "mensagem": "Você atingiu seu limite. Faça upgrade do plano."
            }

        caminho_salvo = salvar_arquivo_upload(arquivo, arquivo.filename)
        hash_sha256 = gerar_hash_arquivo(caminho_salvo)

        registro_existente = (
            db.query(RegistroAutenticidade)
            .filter(RegistroAutenticidade.hash_sha256 == hash_sha256)
            .first()
        )

        # Se já existir registro com esse hash, devolve o que já existe
        if registro_existente is not None:
            dna_status = "nao_aplicado"
            dna_arquivo_url = None

            caminho_dna_png = BASE_DIR / "uploads" / f"{registro_existente.selo_id}_dna.png"
            caminho_dna_pdf = BASE_DIR / "uploads" / f"{registro_existente.selo_id}_dna.pdf"
            caminho_dna_docx = BASE_DIR / "uploads" / f"{registro_existente.selo_id}_dna.docx"

            if caminho_dna_png.exists():
                dna_status = "embutido"
                dna_arquivo_url = f"/dna/arquivo/{registro_existente.selo_id}"
            elif caminho_dna_pdf.exists():
                dna_status = "embutido_pdf"
                dna_arquivo_url = f"/uploads/{registro_existente.selo_id}_dna.pdf"
            elif caminho_dna_docx.exists():
                dna_status = "embutido_docx"
                dna_arquivo_url = f"/uploads/{registro_existente.selo_id}_dna.docx"


            return {
                "id": registro_existente.id,
                "nome_arquivo": registro_existente.nome_arquivo,
                "tipo_arquivo": registro_existente.tipo_arquivo,
                "tamanho_bytes": registro_existente.tamanho_bytes,
                "hash_sha256": registro_existente.hash_sha256,
                "selo_id": registro_existente.selo_id,
                "status": registro_existente.status,
                "criado_em": registro_existente.criado_em.isoformat(),
                "link_validacao": f"{APP_BASE_URL}/verificar/{registro_existente.selo_id}",
                "qr_code_url": f"/uploads/{registro_existente.selo_id}.png",
                "usuario_id": registro_existente.usuario_id,
                "certidao_url": f"/certidao/{registro_existente.selo_id}",
                "dna_status": dna_status,
                "dna_arquivo_url": dna_arquivo_url
            }

        # cria novo registro
        novo_registro = RegistroAutenticidade(
            nome_arquivo=arquivo.filename,
            tipo_arquivo=arquivo.content_type,
            tamanho_bytes=tamanho_arquivo(caminho_salvo),
            hash_sha256=hash_sha256,
            caminho_arquivo=caminho_salvo,
            selo_id=gerar_selo_id(),
            status="autentico",
            usuario_id=usuario.id
        )

        db.add(novo_registro)
        db.commit()
        db.refresh(novo_registro)

        link_validacao = f"{APP_BASE_URL}/verificar/{novo_registro.selo_id}"
        caminho_qr = f"uploads/{novo_registro.selo_id}.png"
        gerar_qrcode(link_validacao, caminho_qr)

        dna_status = "nao_aplicado"
        dna_arquivo_url = None

        nome_lower = (novo_registro.nome_arquivo or "").lower()

        # DNA IMAGEM
        if nome_lower.endswith((".png", ".jpg", ".jpeg", ".webp", ".bmp")):
            try:
                print("APLICANDO DNA NA IMAGEM...")

                dna_texto = gerar_dna_token(
                    selo_id=novo_registro.selo_id,
                    hash_sha256=novo_registro.hash_sha256,
                    usuario_id=novo_registro.usuario_id,
                    tipo_arquivo=novo_registro.tipo_arquivo or "imagem",
                    nome_arquivo=novo_registro.nome_arquivo
                )

                caminho_dna = gerar_arquivo_dna_path(novo_registro.selo_id)
                inserir_dna_imagem(caminho_salvo, caminho_dna, dna_texto)

                dna_status = "embutido"
                dna_arquivo_url = f"/dna/arquivo/{novo_registro.selo_id}"
                print("DNA IMAGEM APLICADO:", caminho_dna)

            except Exception as e:
                import traceback
                print("ERRO IMAGEM:", str(e))
                traceback.print_exc()
                dna_status = "erro"

        # DNA PDF
        elif nome_lower.endswith(".pdf"):
            try:
                print("APLICANDO DNA NO PDF...")

                dna_texto = gerar_dna_token(
                    selo_id=novo_registro.selo_id,
                    hash_sha256=novo_registro.hash_sha256,
                    usuario_id=novo_registro.usuario_id,
                    tipo_arquivo="pdf",
                    nome_arquivo=novo_registro.nome_arquivo
                )

                caminho_pdf_dna = f"uploads/{novo_registro.selo_id}_dna.pdf"
                inserir_dna_pdf(caminho_salvo, caminho_pdf_dna, dna_texto)

                dna_status = "embutido_pdf"
                dna_arquivo_url = f"/uploads/{novo_registro.selo_id}_dna.pdf"
                print("DNA PDF APLICADO:", caminho_pdf_dna)

            except Exception as e:
                import traceback
                print("ERRO PDF:", str(e))
                traceback.print_exc()
                dna_status = "erro_pdf"

        # DNA DOCX
        elif nome_lower.endswith(".docx"):
            try:
                print("APLICANDO DNA NO DOCX...")

                dna_texto = gerar_dna_token(
                    selo_id=novo_registro.selo_id,
                    hash_sha256=novo_registro.hash_sha256,
                    usuario_id=novo_registro.usuario_id,
                    tipo_arquivo="docx",
                    nome_arquivo=novo_registro.nome_arquivo
                )

                caminho_docx_dna = f"uploads/{novo_registro.selo_id}_dna.docx"
                inserir_dna_docx(caminho_salvo, caminho_docx_dna, dna_texto)

                dna_status = "embutido_docx"
                dna_arquivo_url = f"/uploads/{novo_registro.selo_id}_dna.docx"
                print("DNA DOCX APLICADO:", caminho_docx_dna)

            except Exception as e:
                import traceback
                print("ERRO DOCX:", str(e))
                traceback.print_exc()
                dna_status = "erro_docx"

        print("RETORNO FINAL DNA STATUS:", dna_status)
        print("RETORNO FINAL DNA URL:", dna_arquivo_url)

        # 📊 CONTABILIZA USO
        usuario.uso_api += 1
        db.commit()

        return {
            "id": novo_registro.id,
            "nome_arquivo": novo_registro.nome_arquivo,
            "tipo_arquivo": novo_registro.tipo_arquivo,
            "tamanho_bytes": novo_registro.tamanho_bytes,
            "hash_sha256": novo_registro.hash_sha256,
            "selo_id": novo_registro.selo_id,
            "status": novo_registro.status,
            "criado_em": novo_registro.criado_em.isoformat(),
            "link_validacao": link_validacao,
            "qr_code_url": f"/uploads/{novo_registro.selo_id}.png",
            "usuario_id": novo_registro.usuario_id,
            "certidao_url": f"/certidao/{novo_registro.selo_id}",
            "dna_status": dna_status,
            "dna_arquivo_url": dna_arquivo_url
        }

    except HTTPException:
        raise
    except Exception as e:
        import traceback
        print("ERRO GERAL /selar:", str(e))
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Erro ao selar arquivo: {str(e)}")
@app.get("/dna/arquivo/{selo_id}")
def baixar_arquivo_dna(selo_id: str):
    caminho = BASE_DIR / "uploads" / f"{selo_id}_dna.png"

    if not caminho.exists():
        raise HTTPException(status_code=404, detail="Arquivo com DNA não encontrado.")

    return FileResponse(path=str(caminho), media_type="image/png")


@app.post("/dna/verificar-upload")
def verificar_dna_upload(
    request: Request,
    arquivo: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    import os
    import tempfile

    if not arquivo_eh_imagem(arquivo.filename):
        registrar_log_rastreamento(
            db=db,
            request=request,
            rota="/dna/verificar-upload",
            resultado="erro",
            observacao=f"Arquivo não suportado para DNA imagem: {arquivo.filename}"
        )
        raise HTTPException(status_code=400, detail="DNA Oráculo V1 aceita apenas imagens.")

    caminho_temporario = None

    try:
        suffix = Path(arquivo.filename).suffix or ".png"

        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
            tmp.write(arquivo.file.read())
            caminho_temporario = tmp.name

        dna_extraido = extrair_dna_imagem(caminho_temporario)

        # não encontrou DNA
        if not dna_extraido:
            registrar_log_rastreamento(
                db=db,
                request=request,
                rota="/dna/verificar-upload",
                resultado="dna_nao_detectado",
                observacao=f"Nenhum DNA encontrado em {arquivo.filename}"
            )

            return {
                "encontrado": False,
                "validado": False,
                "mensagem": "Nenhum DNA Oráculo foi detectado nesta imagem."
            }

        # valida token
        payload = validar_dna_token(dna_extraido)

        if not payload:
            registrar_log_rastreamento(
                db=db,
                request=request,
                rota="/dna/verificar-upload",
                resultado="dna_detectado_nao_validado",
                observacao=f"DNA detectado mas inválido em {arquivo.filename}"
            )

            return {
                "encontrado": True,
                "validado": False,
                "mensagem": "DNA detectado, mas não foi possível validar."
            }

        selo_id = payload.get("selo_id")
        hash_prefix = payload.get("hash_prefix")
        usuario_id = str(payload.get("usuario_id"))

        registro = (
            db.query(RegistroAutenticidade)
            .filter(RegistroAutenticidade.selo_id == selo_id)
            .first()
        )

        if not registro:
            registrar_log_rastreamento(
                db=db,
                request=request,
                rota="/dna/verificar-upload",
                resultado="dna_valido_sem_registro",
                selo_id=selo_id,
                observacao="DNA válido mas sem registro correspondente."
            )

            return {
                "encontrado": True,
                "validado": False,
                "mensagem": "DNA válido, mas registro não encontrado."
            }

        if not registro.hash_sha256.startswith(hash_prefix):
            registrar_log_rastreamento(
                db=db,
                request=request,
                rota="/dna/verificar-upload",
                resultado="dna_detectado_nao_validado",
                selo_id=selo_id,
                observacao="Hash prefix do DNA não confere com o registro."
            )

            return {
                "encontrado": True,
                "validado": False,
                "mensagem": "DNA detectado, mas o hash não confere com o registro."
            }

        if str(registro.usuario_id) != usuario_id:
            registrar_log_rastreamento(
                db=db,
                request=request,
                rota="/dna/verificar-upload",
                resultado="dna_detectado_nao_validado",
                selo_id=selo_id,
                observacao="Usuário do DNA não confere com o registro."
            )

            return {
                "encontrado": True,
                "validado": False,
                "mensagem": "DNA detectado, mas o usuário não confere com o registro."
            }

        registrar_log_rastreamento(
            db=db,
            request=request,
            rota="/dna/verificar-upload",
            resultado="dna_validado",
            selo_id=registro.selo_id,
            observacao=f"DNA validado com sucesso em {arquivo.filename}"
        )

        return {
            "encontrado": True,
            "validado": True,
            "mensagem": "DNA Oráculo detectado e validado com sucesso.",
            "selo_id": registro.selo_id,
            "hash_sha256": registro.hash_sha256,
            "nome_arquivo_original": registro.nome_arquivo,
            "usuario_id": registro.usuario_id,
            "link_validacao": f"{APP_BASE_URL}/verificar/{registro.selo_id}",
            "certidao_url": f"/certidao/{registro.selo_id}"
        }

    except Exception as e:
        import traceback
        traceback.print_exc()

        registrar_log_rastreamento(
            db=db,
            request=request,
            rota="/dna/verificar-upload",
            resultado="erro",
            observacao=str(e)
        )

        raise HTTPException(status_code=500, detail="Erro ao verificar DNA.")

    finally:
        if caminho_temporario and os.path.exists(caminho_temporario):
            os.remove(caminho_temporario)

@app.get("/meus-registros")
def meus_registros(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    usuario = obter_usuario_por_token(authorization, db)

    registros = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.usuario_id == usuario.id)
        .order_by(RegistroAutenticidade.id.desc())
        .all()
    )

    return registros


@app.get("/api/status")
def status_api(
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    usuario = obter_usuario_por_token(authorization, db)

    restante = usuario.limite_api - usuario.uso_api

    return {
        "email": usuario.email,
        "plano": usuario.plano,
        "uso_api": usuario.uso_api,
        "limite_api": usuario.limite_api,
        "restante": restante,
        "api_key": usuario.api_key
    }


@app.post("/upgrade-plano")
def upgrade_plano(
    plano: str,
    authorization: str | None = Header(default=None),
    db: Session = Depends(get_db)
):
    usuario = obter_usuario_por_token(authorization, db)

    plano = plano.lower().strip()

    if plano == "gratuito":
        usuario.plano = "gratuito"
        usuario.limite_api = 10
    elif plano == "pro":
        usuario.plano = "pro"
        usuario.limite_api = 100
    elif plano == "business":
        usuario.plano = "business"
        usuario.limite_api = 1000
    else:
        raise HTTPException(status_code=400, detail="Plano inválido.")

    db.commit()
    db.refresh(usuario)

    return {
        "mensagem": "Plano atualizado com sucesso.",
        "plano": usuario.plano,
        "limite_api": usuario.limite_api,
        "uso_api": usuario.uso_api,
        "restante": usuario.limite_api - usuario.uso_api
    }


@app.post("/api/selar")
def api_selar(
    arquivo: UploadFile = File(...),
    x_api_key: str = Header(default=None),
    db: Session = Depends(get_db)
):
    usuario = obter_usuario_por_api_key(x_api_key, db)

    if usuario.uso_api >= usuario.limite_api:
        raise HTTPException(
            status_code=403,
            detail="Limite de uso da API atingido. Faça upgrade do plano."
        )

    caminho_salvo = salvar_arquivo_upload(arquivo, arquivo.filename)
    hash_sha256 = gerar_hash_arquivo(caminho_salvo)

    novo_registro = RegistroAutenticidade(
        nome_arquivo=arquivo.filename,
        tipo_arquivo=arquivo.content_type,
        tamanho_bytes=tamanho_arquivo(caminho_salvo),
        hash_sha256=hash_sha256,
        caminho_arquivo=caminho_salvo,
        selo_id=gerar_selo_id(),
        status="autentico",
        usuario_id=usuario.id
    )

    db.add(novo_registro)
    usuario.uso_api += 1

    db.commit()
    db.refresh(novo_registro)

    link_validacao = f"http://127.0.0.1:8000/verificar/{novo_registro.selo_id}"
    caminho_qr = f"uploads/{novo_registro.selo_id}.png"
    gerar_qrcode(link_validacao, caminho_qr)

    print("===================================")
    print("NOME REAL DO ARQUIVO:", repr(novo_registro.nome_arquivo))
    print("MINUSCULO:", repr(novo_registro.nome_arquivo.lower()))
    print("TERMINA COM .docx ?", novo_registro.nome_arquivo.lower().endswith(".docx"))
    print("===================================")

    dna_status = "nao_aplicado"
    dna_arquivo_url = None

    if arquivo_eh_imagem(novo_registro.nome_arquivo):
        try:
            dna_texto = gerar_dna_oraculo(
                novo_registro.selo_id,
                novo_registro.hash_sha256,
                novo_registro.usuario_id
            )
            caminho_dna = gerar_arquivo_dna_path(novo_registro.selo_id)
            inserir_dna_imagem(caminho_salvo, caminho_dna, dna_texto)
            dna_status = "embutido"
            dna_arquivo_url = f"/dna/arquivo/{novo_registro.selo_id}"
        except Exception:
            dna_status = "falha"

    print("RETORNO FINAL DNA STATUS:", dna_status)
    print("RETORNO FINAL DNA URL:", dna_arquivo_url)

    return {
        "selo_id": novo_registro.selo_id,
        "hash_sha256": novo_registro.hash_sha256,
        "link_validacao": link_validacao,
        "qr_code_url": f"/uploads/{novo_registro.selo_id}.png",
        "uso_api": usuario.uso_api,
        "limite_api": usuario.limite_api,
        "certidao_url": f"/certidao/{novo_registro.selo_id}",
        "dna_status": dna_status,
        "dna_arquivo_url": dna_arquivo_url
    }


@app.get("/certidao/{selo_id}")
def baixar_certidao(selo_id: str, db: Session = Depends(get_db)):
    registro = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.selo_id == selo_id)
        .first()
    )

    if not registro:
        raise HTTPException(status_code=404, detail="Certidão não encontrada.")

    usuario = db.query(Usuario).filter(Usuario.id == registro.usuario_id).first()
    email_usuario = usuario.email if usuario else None

    pdf_buffer = gerar_certidao_pdf(registro, email_usuario)

    nome_arquivo = f"certidao_{registro.selo_id}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{nome_arquivo}"'
        }
    )

@app.get("/dna/base/{selo_id}")
def ver_dna_base(selo_id: str, db: Session = Depends(get_db)):
    registro = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.selo_id == selo_id)
        .first()
    )

    if not registro:
        raise HTTPException(status_code=404, detail="Registro não encontrado.")

    dna_token = gerar_dna_token(
        selo_id=registro.selo_id,
        hash_sha256=registro.hash_sha256,
        usuario_id=registro.usuario_id,
        tipo_arquivo=registro.tipo_arquivo or "desconhecido",
        nome_arquivo=registro.nome_arquivo
    )

    payload = validar_dna_token(dna_token)

    return {
        "dna_token": dna_token,
        "dna_payload": payload
    }

@app.post("/dna/verificar-pdf")
def verificar_pdf(
    arquivo: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    caminho_temp = salvar_arquivo_upload(arquivo, arquivo.filename)

    dna_token = extrair_dna_pdf(caminho_temp)

    if not dna_token:
        return {
            "valido": False,
            "mensagem": "Nenhum DNA Oráculo encontrado no PDF."
        }

    payload = validar_dna_token(dna_token)

    if not payload:
        return {
            "valido": False,
            "mensagem": "DNA inválido ou corrompido."
        }

    registro = localizar_registro_por_dna(dna_token, db)

    if not registro:
        return {
            "valido": False,
            "mensagem": "Registro não encontrado."
        }

    return {
        "valido": True,
        "mensagem": "Documento autêntico",
        "registro": {
            "selo_id": registro.selo_id,
            "arquivo": registro.nome_arquivo,
            "data": registro.criado_em
        }
    }

@app.post("/dna/verificar-docx")
def verificar_docx(
    arquivo: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    caminho_temp = salvar_arquivo_upload(arquivo, arquivo.filename)

    dna_info = extrair_dna_docx(caminho_temp)

    if not dna_info:
        return {
            "valido": False,
            "mensagem": "Nenhum DNA Oráculo encontrado no DOCX."
        }

    selo_id = dna_info.get("selo_id")
    hash_prefix = dna_info.get("hash_prefix")
    usuario_id = str(dna_info.get("usuario_id"))

    registro = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.selo_id == selo_id)
        .first()
    )

    if not registro:
        return {
            "valido": False,
            "mensagem": "Registro não encontrado."
        }

    if not registro.hash_sha256.startswith(hash_prefix):
        return {
            "valido": False,
            "mensagem": "Hash do DOCX não confere com o registro."
        }

    if str(registro.usuario_id) != usuario_id:
        return {
            "valido": False,
            "mensagem": "Usuário do DOCX não confere com o registro."
        }

    return {
        "valido": True,
        "mensagem": "Documento DOCX autêntico",
        "registro": {
            "selo_id": registro.selo_id,
            "arquivo": registro.nome_arquivo,
            "data": registro.criado_em
        }
    }

@app.get("/validar/hash/{hash_value}")
def validar_por_hash(hash_value: str, db: Session = Depends(get_db)):
    registro = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.hash_sha256 == hash_value)
        .first()
    )

    if not registro:
        return {
            "encontrado": False,
            "autentico": False,
            "mensagem": "Nenhum registro encontrado para este hash."
        }

    return {
        "encontrado": True,
        "autentico": registro.status == "autentico",
        "mensagem": "Arquivo localizado e validado no Oráculo.",
        "registro": {
            "id": registro.id,
            "nome_arquivo": registro.nome_arquivo,
            "hash_sha256": registro.hash_sha256,
            "selo_id": registro.selo_id,
            "status": registro.status
        }
    }


@app.get("/validar/selo/{selo_id}")
def validar_por_selo(selo_id: str, request: Request, db: Session = Depends(get_db)):
    registro = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.selo_id == selo_id)
        .first()
    )

    if not registro:
        registrar_log_rastreamento(
            db=db,
            request=request,
            rota="/validar/selo/{selo_id}",
            resultado="nao_encontrado",
            selo_id=selo_id,
            observacao="Selo não localizado."
        )

        return {
            "encontrado": False,
            "autentico": False,
            "mensagem": "Nenhum registro encontrado para este selo."
        }

    registrar_log_rastreamento(
        db=db,
        request=request,
        rota="/validar/selo/{selo_id}",
        resultado="autentico" if registro.status == "autentico" else "nao_autentico",
        selo_id=selo_id,
        observacao="Validação por selo executada."
    )

    return {
        "encontrado": True,
        "autentico": registro.status == "autentico",
        "mensagem": "Selo localizado e validado no Oráculo.",
        "registro": {
            "id": registro.id,
            "nome_arquivo": registro.nome_arquivo,
            "hash_sha256": registro.hash_sha256,
            "selo_id": registro.selo_id,
            "status": registro.status
        }
    }


@app.get("/registros")
def listar_registros(db: Session = Depends(get_db)):
    registros = db.query(RegistroAutenticidade).order_by(RegistroAutenticidade.id.desc()).all()
    return registros


@app.get("/verificar/{selo_id}", response_class=HTMLResponse)
def verificar_selo(selo_id: str, request: Request, db: Session = Depends(get_db)):
    registro = (
        db.query(RegistroAutenticidade)
        .filter(RegistroAutenticidade.selo_id == selo_id)
        .first()
    )

    if not registro:
        registrar_log_rastreamento(
            db=db,
            request=request,
            rota="/verificar/{selo_id}",
            resultado="nao_encontrado",
            selo_id=selo_id,
            observacao="Selo não localizado na verificação pública."
        )
        return """
        <html>
        <body style="background:#0a0f1f;color:white;text-align:center;margin-top:100px;font-family:Arial;">
            <h1 style="color:#f87171;">❌ NÃO ENCONTRADO</h1>
            <p>Este selo não existe no Passaporte Oráculo.</p>
        </body>
        </html>
        """
    registrar_log_rastreamento(
        db=db,
        request=request,
        rota="/verificar/{selo_id}",
        resultado="autentico",
        selo_id=selo_id,
        observacao="Validação pública acessada com sucesso."
    )

    return f"""
    <html>
    <head>
        <title>Validação Oráculo</title>
        <style>
            body {{
                margin:0;
                font-family:Arial;
                background:linear-gradient(135deg,#060b16,#0a0f1f,#101a33);
                color:white;
            }}
            .container {{
                max-width:800px;
                margin:80px auto;
                padding:20px;
            }}
            .card {{
                background:#111827;
                padding:30px;
                border-radius:20px;
                box-shadow:0 0 30px rgba(0,212,255,0.15);
            }}
            h1 {{
                text-align:center;
                color:#00d4ff;
            }}
            .status {{
                text-align:center;
                font-size:26px;
                color:#4ade80;
                margin-bottom:25px;
            }}
            .row {{
                margin-bottom:15px;
            }}
            .label {{
                color:#7dd3fc;
                font-weight:bold;
            }}
            .value {{
                color:#e5eefb;
                word-break:break-word;
            }}
            .footer {{
                text-align:center;
                margin-top:30px;
                color:#94a3b8;
                font-size:14px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="card">
                <h1>💎 Passaporte Oráculo</h1>
                <div class="status">✅ AUTÊNTICO</div>

                <div class="row">
                    <div class="label">Arquivo</div>
                    <div class="value">{registro.nome_arquivo}</div>
                </div>

                <div class="row">
                    <div class="label">Selo</div>
                    <div class="value">{registro.selo_id}</div>
                </div>

                <div class="row">
                    <div class="label">Hash</div>
                    <div class="value">{registro.hash_sha256}</div>
                </div>

                <div class="row">
                    <div class="label">Criado em</div>
                    <div class="value">{registro.criado_em}</div>
                </div>

                <div class="footer">
                    Registro confirmado e protegido pelo protocolo Oráculo.
                </div>
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/rastreamento/logs")
def listar_logs_rastreamento(db: Session = Depends(get_db)):
    logs = db.query(LogRastreamento).order_by(LogRastreamento.id.desc()).all()
    return logs

@app.get("/rastreamento/fraude")
def analisar_fraude(db: Session = Depends(get_db)):
    logs = db.query(LogRastreamento).order_by(LogRastreamento.id.desc()).all()

    analise = {}

    for log in logs:
        chave = log.selo_id or log.hash_consultado or "desconhecido"

        if chave not in analise:
            analise[chave] = {
                "referencia": chave,
                "total_acessos": 0,
                "ips_unicos": set(),
                "tentativas_invalidas": 0,
                "consultas_nao_encontradas": 0,
                "dna_invalido": 0,
                "dna_nao_detectado": 0,
                "fraude_suspeita": False,
                "motivos": []
            }

        item = analise[chave]
        item["total_acessos"] += 1

        if log.ip_origem:
            item["ips_unicos"].add(log.ip_origem)

        if log.resultado in ["nao_encontrado", "dna_detectado_nao_validado", "dna_valido_sem_registro", "erro"]:
            item["tentativas_invalidas"] += 1

        if log.resultado == "nao_encontrado":
            item["consultas_nao_encontradas"] += 1

        if log.resultado in ["dna_detectado_nao_validado", "dna_valido_sem_registro"]:
            item["dna_invalido"] += 1

        if log.resultado == "dna_nao_detectado":
            item["dna_nao_detectado"] += 1

    # aplicar regras
    for chave, item in analise.items():
        total_ips = len(item["ips_unicos"])

        if item["total_acessos"] >= 10:
            item["fraude_suspeita"] = True
            item["motivos"].append("Alto volume de acessos")

        if total_ips >= 3:
            item["fraude_suspeita"] = True
            item["motivos"].append("Múltiplos IPs consultando o mesmo selo/hash")

        if item["tentativas_invalidas"] >= 3:
            item["fraude_suspeita"] = True
            item["motivos"].append("Múltiplas tentativas inválidas")

        if item["dna_invalido"] >= 2:
            item["fraude_suspeita"] = True
            item["motivos"].append("DNA inválido ou sem registro repetido")

        item["ips_unicos"] = list(item["ips_unicos"])
        item["total_ips"] = total_ips

        # 🎯 SCORE DE RISCO REAL

        score = 0

        # Volume de acessos (peso progressivo)
        if item["total_acessos"] >= 50:
            score += 10
        elif item["total_acessos"] >= 20:
            score += 5
        elif item["total_acessos"] >= 10:
            score += 3

        # IPs diferentes (comportamento suspeito)
        if total_ips >= 5:
            score += 10
        elif total_ips >= 3:
            score += 5

        # Tentativas inválidas
        score += item["tentativas_invalidas"] * 5

        # DNA inválido (muito crítico)
        score += item["dna_invalido"] * 10

        # 🚨 BONUS: se já marcou como suspeito
        if item.get("fraude_suspeita"):
            score += 5

        # Definição de nível
        if score >= 20:
            nivel = "ALTO"
        elif score >= 10:
            nivel = "MÉDIO"
        else:
            nivel = "BAIXO"

        item["score_risco"] = score
        item["nivel_risco"] = nivel

        # 🚨 BLOQUEIO AUTOMÁTICO
        if score >= 40:
            try:
                registro = db.query(RegistroAutenticidade).filter(
                    RegistroAutenticidade.selo_id == item["referencia"]
                ).first()

                if registro:
                    registro.status = "bloqueado"
                    db.commit()
                    print("SELO BLOQUEADO AUTOMATICAMENTE:", item["referencia"])
            except Exception as e:
                print("Erro ao bloquear selo:", str(e))

        # 🚨 ALERTA AQUI
        if item["score_risco"] >= 20:
            try:
                enviar_alerta_email(
                    destino="luizcarlosphh@gmail.com",
                    assunto="🚨 ALERTA DE FRAUDE - ORÁCULO",
                    mensagem=f"""
        Possível fraude detectada!

        Referência: {item["referencia"]}
        Score: {item["score_risco"]}
        IPs: {item["ips_unicos"]}

        Motivos:
        {", ".join(item["motivos"])}
        """
                )
            except Exception as e:
                print("Erro ao disparar alerta:", str(e))

    return analise

@app.get("/rastreamento/fraude/suspeitos")
def listar_suspeitos_fraude(db: Session = Depends(get_db)):
    logs = db.query(LogRastreamento).order_by(LogRastreamento.id.desc()).all()

    analise = {}

    for log in logs:
        chave = log.selo_id or log.hash_consultado or "desconhecido"

        if chave not in analise:
            analise[chave] = {
                "referencia": chave,
                "total_acessos": 0,
                "ips_unicos": set(),
                "tentativas_invalidas": 0,
                "dna_invalido": 0,
                "fraude_suspeita": False,
                "motivos": []
            }

        item = analise[chave]
        item["total_acessos"] += 1

        if log.ip_origem:
            item["ips_unicos"].add(log.ip_origem)

        if log.resultado in ["nao_encontrado", "dna_detectado_nao_validado", "dna_valido_sem_registro", "erro"]:
            item["tentativas_invalidas"] += 1

        if log.resultado in ["dna_detectado_nao_validado", "dna_valido_sem_registro"]:
            item["dna_invalido"] += 1

    suspeitos = []

    for chave, item in analise.items():
        total_ips = len(item["ips_unicos"])

        if item["total_acessos"] >= 10:
            item["fraude_suspeita"] = True
            item["motivos"].append("Alto volume de acessos")

        if total_ips >= 3:
            item["fraude_suspeita"] = True
            item["motivos"].append("Múltiplos IPs")

        if item["tentativas_invalidas"] >= 3:
            item["fraude_suspeita"] = True
            item["motivos"].append("Tentativas inválidas repetidas")

        if item["dna_invalido"] >= 2:
            item["fraude_suspeita"] = True
            item["motivos"].append("DNA inválido repetido")

        # SCORE DE RISCO
        score = 0

        if item["total_acessos"] >= 50:
            score += 10
        elif item["total_acessos"] >= 20:
            score += 5
        elif item["total_acessos"] >= 10:
            score += 3

        if total_ips >= 5:
            score += 10
        elif total_ips >= 3:
            score += 5

        score += item["tentativas_invalidas"] * 5
        score += item["dna_invalido"] * 10

        if item["fraude_suspeita"]:
            score += 5

        if score >= 20:
            nivel = "ALTO"
        elif score >= 10:
            nivel = "MÉDIO"
        else:
            nivel = "BAIXO"

        item["score_risco"] = score
        item["nivel_risco"] = nivel
        item["ips_unicos"] = list(item["ips_unicos"])
        item["total_ips"] = total_ips

        if item["fraude_suspeita"]:
            suspeitos.append(item)

    return suspeitos

@app.get("/rastreamento/alertas")
def alertas_criticos(db: Session = Depends(get_db)):
    logs = db.query(LogRastreamento).order_by(LogRastreamento.id.desc()).limit(50).all()

    alertas = []

    for log in logs:
        if log.resultado in [
            "dna_detectado_nao_validado",
            "dna_valido_sem_registro",
            "erro"
        ]:
            alertas.append({
                "selo_id": log.selo_id,
                "rota": log.rota,
                "ip": log.ip_origem,
                "resultado": log.resultado,
                "quando": log.criado_em,
                "observacao": log.observacao
            })

    return alertas

@app.get("/uploads/{nome_arquivo}")
def servir_upload(nome_arquivo: str):
    caminho = BASE_DIR / "uploads" / nome_arquivo

    if not caminho.exists():
        raise HTTPException(status_code=404, detail=f"Arquivo não encontrado: {caminho}")

    return FileResponse(path=str(caminho))

@app.get("/rastreamento/analise")
def analisar_comportamento(db: Session = Depends(get_db)):
    logs = db.query(LogRastreamento).all()

    analise = {}

    for log in logs:
        chave = log.selo_id or log.hash_consultado or "desconhecido"

        if chave not in analise:
            analise[chave] = {
                "total_acessos": 0,
                "ips": set(),
                "suspeito": False
            }

        analise[chave]["total_acessos"] += 1

        if log.ip_origem:
            analise[chave]["ips"].add(log.ip_origem)

        # 🚨 REGRA DE SUSPEITA
        if analise[chave]["total_acessos"] > 10:
            analise[chave]["suspeito"] = True

        if len(analise[chave]["ips"]) > 3:
            analise[chave]["suspeito"] = True

    # converter sets pra lista
    for chave in analise:
        analise[chave]["ips"] = list(analise[chave]["ips"])

    return analise

@app.get("/upgrade")
def upgrade_plano():
    return {
        "mensagem": "Para liberar mais usos, faça o pagamento via Pix.",
        "pix": {
            "chave": "SEU_PIX_AQUI",
            "valor": "29.90",
            "descricao": "Upgrade Plano Oráculo PRO"
        }
    }

@app.post("/admin/add-credito/{user_id}")
def add_credito(user_id: int, valor: int, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()

    if not usuario:
        return {"erro": "usuario_nao_encontrado"}

    usuario.limite_api += valor
    db.commit()

    return {"ok": True}


@app.post("/admin/bloquear/{user_id}")
def bloquear_usuario(user_id: int, db: Session = Depends(get_db)):
    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()

    if not usuario:
        return {"erro": "usuario_nao_encontrado"}

    usuario.limite_api = 0
    db.commit()

    return {"ok": True}


@app.delete("/admin/excluir-usuario")
def excluir_usuario(
    user_id: int,
    admin_token: str = Query(...),
    db: Session = Depends(get_db)
):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Acesso negado.")

    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()

    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    db.delete(usuario)
    db.commit()

    return {"mensagem": "Usuário excluído com sucesso"}

@app.get("/admin/planos")
def listar_planos(
    admin_token: str = Query(...),
    db: Session = Depends(get_db)
):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Acesso negado.")

    planos = db.query(Plano).all()

    return [
        {
            "id": p.id,
            "nome": p.nome,
            "limite_api": p.limite_api,
            "ativo": p.ativo
        }
        for p in planos
    ]

@app.post("/admin/trocar-plano")
def trocar_plano_usuario(
    user_id: int,
    nome_plano: str,
    admin_token: str = Query(...),
    db: Session = Depends(get_db)
):
    if admin_token != ADMIN_TOKEN:
        raise HTTPException(status_code=403, detail="Acesso negado.")

    usuario = db.query(Usuario).filter(Usuario.id == user_id).first()
    if not usuario:
        raise HTTPException(status_code=404, detail="Usuário não encontrado.")

    plano = db.query(Plano).filter(Plano.nome == nome_plano, Plano.ativo == True).first()
    if not plano:
        raise HTTPException(status_code=404, detail="Plano não encontrado.")

    usuario.plano = plano.nome
    usuario.limite_api = plano.limite_api
    db.commit()
    db.refresh(usuario)

    return {
        "mensagem": "Plano atualizado com sucesso.",
        "usuario_id": usuario.id,
        "email": usuario.email,
        "plano": usuario.plano,
        "limite_api": usuario.limite_api
    }