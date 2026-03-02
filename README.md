# Agenda Escolar PRO

Sistema web profissional para gestão de reservas de salas e equipamentos com foco em segurança, auditoria e operação real.

## Stack
- Python 3.10+
- Flask 3
- SQLite
- Jinja2 + CSS responsivo
- Chart.js (painel analítico)
- Pytest (testes automatizados)
- Waitress (servidor produção)

## Melhorias avançadas aplicadas

### 1) Essenciais de produto
- Soft delete de usuários, salas e equipamentos.
- Paginação em telas administrativas críticas (usuários, reservas, logs).
- Ordenação e busca no módulo de usuários.
- Validações robustas de reserva:
  - sem data passada,
  - janela de horário configurável,
  - duração máxima configurável,
  - conflito de horário bloqueado.
- Auditoria com payload antes/depois para mudanças sensíveis.

### 2) Segurança
- CSRF em todos os formulários POST.
- Rate limit de login por email+IP.
- Política de senha forte (8+, maiúscula, minúscula, número, símbolo).
- Troca obrigatória de senha inicial (configurada no admin default).
- Sessão com timeout por inatividade.
- Security headers (CSP, X-Frame-Options, etc).

### 3) Funcionalidade e integração
- API JSON de reservas (`/api/reservas`).
- Endpoint de documentação da API (`/api/docs`).
- Exportação CSV de reservas e relatórios.
- Dashboard analítico com gráficos.

### 4) UX/Admin
- Filtro por perfil de usuário + contadores por tipo.
- Busca por nome/email em usuários.
- Badges visuais por perfil.
- Paginação com controles em múltiplas telas.

### 5) Qualidade técnica
- Configurações por ambiente via variáveis (`AGENDA_SECRET_KEY`) e `config.py` opcional.
- Índices de banco para consultas críticas.
- Testes cobrindo autenticação, permissão, conflito e política de senha.

### 6) Operação / Deploy
- `Dockerfile` pronto.
- `docker-compose.yml` pronto.
- CI com GitHub Actions em `.github/workflows/ci.yml`.
- `serve.py` com Waitress para execução de produção.

## Estrutura
- `app/views.py` regras de negócio e rotas.
- `app/db.py` banco, comandos CLI e seed.
- `app/schema.sql` estrutura e índices.
- `app/templates/` interface.
- `tests/` suíte automatizada.

## Execução local (dev)
1. Criar ambiente virtual:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   ```
2. Instalar dependências:
   ```powershell
   pip install -r requirements.txt
   ```
3. Inicializar banco:
   ```powershell
   flask --app run.py init-db
   ```
4. Popular dados de demonstração:
   ```powershell
   flask --app run.py seed-demo
   ```
5. Rodar app:
   ```powershell
   flask --app run.py run --debug
   ```

## Execução produção local
```powershell
python serve.py
```
Acesse: `http://127.0.0.1:8000`

## Docker
```bash
docker compose up --build
```

## Testes
```powershell
python -m pytest -q
```

## Contas iniciais
- Admin: `admin@escola.local` / `admin123` (troca de senha obrigatória no primeiro login)
- Professor demo (após seed): `ana.prof@escola.local` / `123456`

## Endpoints principais
- `GET /health`
- `GET /api/docs`
- `GET /api/reservas`
- `GET /reservas/exportar.csv`
- `GET /admin/relatorios/exportar/salas.csv`
- `GET /admin/relatorios/exportar/equipamentos.csv`
- `GET /admin/relatorios/exportar/professores.csv`

## Próximo passo recomendado
Antes de venda: ativar banco externo (PostgreSQL), HTTPS obrigatório e revisão completa de cibersegurança aplicada ao ambiente.
