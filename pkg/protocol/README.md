# Master protocol package

This public package exposes the same versioned wire types, strict decoders,
configuration validation, account labels and schemas used by the agent.
Masters can import it without depending on private implementation packages.
`types.go` provides contract aliases; `codec.go` provides validation and codec
entry points. Domain state, networking and runtime lifecycles remain outside
this package. Pin an agent revision and negotiate optional capabilities before
transmitting new fields.
