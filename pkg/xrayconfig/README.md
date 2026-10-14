# Native configuration validation

`Validate` and `Render` run the same preparation used by the agent and its pinned
Xray core. They do not start listeners, execute utility jobs or fetch assets.
Referenced certificate/geodata files need to exist in the validation environment;
masters must distinguish unavailable node-local assets from structural errors.
Rendered JSON contains managed credentials and is an internal secret artifact.
