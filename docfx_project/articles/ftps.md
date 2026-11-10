---
uid: ftps
title: FTP over SSL/TLS
---

# Introduction

The FTPS support enables encrypted communication with the server.

# How to use FTPS

FTPS is automatically enabled as soon as you have set an X509 certificate with private key (read: the `X509Certificate2` from a `.pfx`/`.pkcs12` file) in the [AuthTlsOptions](xref:FubarDev.FtpServer.AuthTlsOptions).

# Example

```csharp
var cert = new X509Certificate2("my.pfx", "my-super-strong-password-that-nobody-knows");
services.Configure<AuthTlsOptions>(cfg => cfg.ServerCertificate = cert);
```

# Requiring TLS

By default, FTPS is only ever *offered*: a client may still log in and transfer data in
plaintext. Two opt-in, default-`false` [AuthTlsOptions](xref:FubarDev.FtpServer.AuthTlsOptions)
flags close that gap:

- `RequireTlsForLogin` rejects `USER`/`PASS`/`ACCT` (and anything else that isn't part of
  the pre-login command set) with `530` until the control connection has been secured with
  `AUTH TLS`. A command that merely *requires login* (e.g. `PWD`) isn't covered by this
  flag directly - since login was never reached, it answers with the ordinary
  `530 Not logged in.` instead of the TLS-specific message.
- `RequireProtectedDataConnections` rejects every command that opens a data connection
  (`RETR`, `STOR`, `APPE`, `LIST`, `NLST`, `MLSD`, `SITE BLST`, ...) with `521` until the
  client has selected `PROT P`. It does **not**, by itself, protect credentials (that's
  `RequireTlsForLogin`'s job) or control-channel listings that never open a data
  connection, such as `STAT <path>` or `MLST` - those travel over the control connection
  and are only as safe as `RequireTlsForLogin` makes it.

```csharp
services.Configure<AuthTlsOptions>(cfg =>
{
    cfg.ServerCertificate = cert;
    cfg.RequireTlsForLogin = true;
    cfg.RequireProtectedDataConnections = true;
});
```

They are independent: enable one, both, or neither, depending on how strict the deployment
needs to be. Both default to `false` so existing deployments keep accepting plaintext unless
they opt in. For a meaningful guarantee, enable both together - `RequireProtectedDataConnections`
alone still lets a client log in, and list or `STAT` a directory, in plaintext.

# Epilogue

You can test this - like many other things - using the sample application in the repository.
