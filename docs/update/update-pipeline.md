# Update Pipeline

The first updater implementation intentionally uses the conservative full-CVD route.

```text
local database
    |
    v
read local version
    |
    v
GET remote CVD
    |
    v
parse remote header
    |
    +---- remote <= local ----> UpToDate
    |
    v
extract into isolated validation directory
    |
    v
parse extracted signature databases
    |
    v
atomic replace
    |
    v
Updated
```

Incremental CDIFF is implemented by `CdiffPatchApplier`, called by `DatabaseUpdater` from `ClamGuard.Database/Update`. Internal ClamAV radix-64 SHA-256 PSS2 signatures are verified before application, and optional `.cdiff.sign` CMS/PKCS#7 verification is available when a certificate directory is configured.
