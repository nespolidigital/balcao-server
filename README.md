# balcao-server

Valida as assinaturas do Balcão na Google Play Developer API e devolve ao app
um estado Premium assinado (HMAC-SHA256).

## Rodar local

```
npm install
copy env.example .env      (Windows)  /  cp env.example .env
npm run dev:server
```

## Render

- New > Web Service, apontando para este repositório
- Build: `npm install` · Start: `npm start`
- Environment: `APP_SECRET`, `PREMIUM_SIGNING_SECRET`, `ANDROID_PACKAGE_NAME`,
  `GOOGLE_SERVICE_ACCOUNT_JSON` (ver `env.example`)
- O endereço do serviço vai no `.env` do app, em `VITE_SERVER_URL`

## Play Console

Assinatura com ID de produto `balcao_premium` e planos básicos `monthly` e
`yearly`, sem oferta de teste grátis. A conta de serviço precisa ter
acesso ao app (ver dados financeiros e gerenciar pedidos e assinaturas).
