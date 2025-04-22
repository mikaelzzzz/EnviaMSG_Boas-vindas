"""
Webhook ZapSign  ➜  consulta Notion  ➜  envia WhatsApp via Z‑API
Versão SINGLE FILE para rodar em Render, Railway ou local.
"""

import re, hmac, hashlib, httpx
from typing import List, Optional

from fastapi import FastAPI, Request, HTTPException, status
from pydantic import BaseModel
from pydantic_settings import BaseSettings


# ───────────────────────── Config via ENV ─────────────────────────
class Settings(BaseSettings):
    # Notion
    NOTION_TOKEN: str
    NOTION_DB_ID: str
    NOTION_VERSION: str = "2022-06-28"

    # Z‑API (WhatsApp)
    ZAPI_INSTANCE_ID: str
    ZAPI_TOKEN: str

    # (Opcional) HMAC ZapSign
    ZAPSIGN_HMAC_SECRET: str | None = None

    class Config:
        env_file = ".env"

settings = Settings()


# ───────────────────── Modelos Pydantic ───────────────────────────
class ResendAttempts(BaseModel):
    whatsapp: int
    email: int
    sms: int


class Signer(BaseModel):
    token: str
    status: str
    name: str
    email: str
    phone_country: str
    phone_number: str
    times_viewed: int
    signed_at: Optional[str] = None
    resend_attempts: ResendAttempts


class Answer(BaseModel):
    variable: str
    value: str


class WebhookPayload(BaseModel):
    event_type: str
    status: str                  # "signed" | "pending"
    name: str                    # nome do PDF
    token: str                   # token do documento
    signers: List[Signer]
    answers: Optional[List[Answer]] = []
    signer_who_signed: Signer


# ───────────────────── Utilidades ─────────────────────────────────
async def notion_search_student(email: str, full_name: str) -> bool:
    """True se o aluno já existe no banco Notion."""
    hdr = {
        "Authorization": f"Bearer {settings.NOTION_TOKEN}",
        "Notion-Version": settings.NOTION_VERSION,
        "Content-Type": "application/json",
    }

    async with httpx.AsyncClient(timeout=10) as cli:
        # 1) busca por e‑mail exato
        q1 = {"filter": {"property": "Email", "rich_text": {"equals": email}}}
        r = await cli.post(
            f"https://api.notion.com/v1/databases/{settings.NOTION_DB_ID}/query",
            headers=hdr, json=q1
        )
        r.raise_for_status()
        if r.json()["results"]:
            return True

        # 2) se não achar, busca por primeiro nome
        first = full_name.split()[0]
        q2 = {"filter": {"property": "Student Name",
                         "rich_text": {"contains": first}}}
        r = await cli.post(
            f"https://api.notion.com/v1/databases/{settings.NOTION_DB_ID}/query",
            headers=hdr, json=q2
        )
        r.raise_for_status()
        return bool(r.json()["results"])


async def send_whatsapp(phone: str, msg: str):
    """Dispara texto simples na Z‑API."""
    phone_digits = re.sub(r"\D", "", phone)
    url = (f"https://api.z-api.io/instances/{settings.ZAPI_INSTANCE_ID}"
           f"/token/{settings.ZAPI_TOKEN}/send-message")
    payload = {"phone": phone_digits, "message": msg}

    async with httpx.AsyncClient(timeout=10) as cli:
        r = await cli.post(url, json=payload)
        r.raise_for_status()


def verify_signature(body: bytes, header: str | None) -> bool:
    """Valida HMAC‑SHA256 ZapSign (header X‑Hub‑Signature‑256)."""
    if not settings.ZAPSIGN_HMAC_SECRET or not header:
        return True
    expected = hmac.new(
        settings.ZAPSIGN_HMAC_SECRET.encode(), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, header)


# ───────────────────── FastAPI ────────────────────────────────────
app = FastAPI()


@app.get("/")
async def root():
    return {"status": "ok"}


@app.post("/webhook/zapsign", status_code=204)
async def webhook(request: Request):
    raw = await request.body()

    # 1) HMAC (opcional, mas seguro)
    if not verify_signature(raw, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(status_code=401, detail="Invalid signature")

    # 2) Valida conteúdo JSON
    try:
        data = WebhookPayload.model_validate_json(raw)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Bad payload: {e}")

    # 3) Ignora eventos enquanto faltam assinaturas
    if data.status != "signed":
        return

    s = data.signer_who_signed
    full_name, email = s.name.strip(), s.email.lower()
    phone = f"+{s.phone_country}{s.phone_number}"
    first = full_name.split()[0]

    # 4) Novo × Renovação
    already = await notion_search_student(email, full_name)

    if already:
        msg = (f"Olá {first}, parabéns pela escolha de continuar seus estudos. "
               "Tenho certeza de que a continuação dessa jornada será incrível. "
               "Já sabe, não é? Se precisar de algo, pode contar com a gente! Rumo à fluência!")
    else:
        answers = {a.variable.lower(): a.value for a in data.answers}
        nome_filho = answers.get("nome completo", "sua filha")
        msg = (
            f"Welcome {first}! 🎉 Parabéns pela excelente decisão para {nome_filho}! "
            "Tenho certeza de que será uma experiência incrível para vocês!\n\n"
            "Sou Marcello, seu ponto de contato para tudo o que precisar da Escola Karol Elói Language Learning. "
            "Estou aqui para garantir que sua filha tenha uma jornada fluida, produtiva e cheia de progresso.\n\n"
            f"Vi que o e‑mail cadastrado é {email}. Você deseja usá-lo para tudo ou prefere trocar? "
            "Lembrando que será somente um e‑mail para todas as plataformas."
        )

    # 5) Envia WhatsApp (não bloqueia o webhook)
    await send_whatsapp(phone, msg)
