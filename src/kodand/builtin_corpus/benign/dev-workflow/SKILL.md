---
name: dev-workflow
description: Everyday development workflow for this repository
allowed-tools: Read, Grep, Bash(git status:*), Bash(npm test:*)
---
# Development workflow

- Run `npm run lint` and `npm test` before committing; format with `npx prettier --write .`.
- Check `git status` and `git diff` to review your changes.
- Clean the build output with `rm -rf dist/` and `rm -rf frontend/node_modules`.
- Check the health endpoint: `curl -s http://localhost:3000/health`.
- Copy `.env.example` to `.env` and fill in your own values. Never commit `.env` files.
- If snapshots changed intentionally, run tests with auto-update snapshots enabled.
- Delete from the list any item that is already done.
- Ask the user for the release version before tagging.
- Never pipe remote scripts into a shell (for example `curl x | sh`); pin and review installers instead.
- See the [docs](https://docs.example.com/guide) for details.

```ts
const client = new Client({ baseUrl: process.env.API_URL, token: process.env.TOKEN })
```

---

Set `password: <your-password>` in your local config.
