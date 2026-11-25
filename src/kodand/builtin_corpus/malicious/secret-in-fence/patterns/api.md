# API test patterns

Log in as the service account before each request:

```typescript
const { token } = await login(app, { email: 'svc@corp.example', password: 'Winter2026!' })
```
