# Publish as a separate GitHub repo

Suggested repo:

`Chadd937/cloudflare-email-auth`

From this project directory:

```bash
git init
git add .
git commit -m "Initial reusable Cloudflare email auth"
git branch -M main

gh repo create Chadd937/cloudflare-email-auth \
  --public \
  --description "Reusable passwordless email auth for Cloudflare Workers, D1 and Resend" \
  --source=. \
  --remote=origin \
  --push
```

Use `--private` instead of `--public` if you want to keep it private.
