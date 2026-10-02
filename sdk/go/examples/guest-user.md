# Explicit guest account provisioning

`CreateMachine` provisions no account by default. Omitted guest user inspection
is `nil`, and default guest sessions use root. To provision a nonroot VM account:

```go
machine, err := runtime.CreateMachine(ctx, silo.OCIImage(image),
    silo.WithName("dev"),
    silo.WithGuestUser("nickvd", 1000, 1000, "/home/nickvd"))
```

The home is a guest path. The native agent provisions the explicit account with
Bash; use an image containing Bash. Existing stored accounts remain unchanged.
`WithExecUser("root")` selects an existing account and does not provision one.
