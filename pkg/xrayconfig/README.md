# Native configuration validation

`Validate` and `Render` run the same preparation used by the agent and its pinned
Xray core. They do not start listeners, execute utility jobs or fetch assets.
Referenced certificate/geodata files need to exist in the validation environment;
masters must distinguish unavailable node-local assets from structural errors.
Rendered JSON contains managed credentials and is an internal secret artifact.
# Incremental validation

`Validator.Validate` preserves the existing validation contract while retaining
one successful immutable prepared candidate. Use a separate validator per
owner/node context. It rechecks local TLS material and builds only changed native
sections; `Counts` reports upstream builder calls. Instances never bind listeners,
issue certificates, activate synthetic previews or persist generated documents.
The original package-level `Validate` remains available for isolated callers.
