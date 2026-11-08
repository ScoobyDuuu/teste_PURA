#!/usr/bin/env bash
# Protege a branch main (exige PR, 1 aprovação e os checks do CI). Requer GitHub CLI autenticado (gh auth login)
# e permissão de administrador no repositório. Uso: tools/github_setup.sh <dono>/<repositorio>
set -euo pipefail
REPO="${1:?uso: tools/github_setup.sh <dono>/<repositorio>}"
gh api -X PUT "repos/${REPO}/branches/main/protection" --input - <<JSON
{
  "required_status_checks": {"strict": true, "contexts": ["lint", "test (3.10)", "test (3.12)", "docker"]},
  "enforce_admins": true,
  "required_pull_request_reviews": {"required_approving_review_count": 1, "require_code_owner_reviews": false,
                                    "dismiss_stale_reviews": true},
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false
}
JSON
echo "main protegida em ${REPO}. Confira em Settings > Branches."
