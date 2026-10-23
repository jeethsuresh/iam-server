# Shared deployment

## Private shared deployment tooling

The deployment job checks out `jeethsuresh/gravitas-deploy` at a full commit SHA,
using this repository’s read-only tooling key from the main-only `gravitas`
environment. `.gravitas/deploy.json` selects this app’s existing release script;
its migrations, manifests and public checks remain in this repository. The shared
action checks namespace permissions, exact image digest, readiness and HTTPS,
and removes its temporary kubeconfig on failure or success. Build/test jobs are
unchanged. Review a new tooling pin before updating it. New-app onboarding is
documented in the private tooling repository.
