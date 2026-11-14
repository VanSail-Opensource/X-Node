# Local signing helper

This build-time helper is not installed on agents. Production release signing
uses the isolated distribution Minisign workflow; its interoperability regression
stays in this package.

Key generation requires two distinct, absent output paths. Existing files and
symlinks are refused, and exclusive creation closes the preflight race. Private
keys use mode 0600. Both file contents and directory entries are synced before
success. A later output failure retains newly written recovery evidence rather
than deleting a private key; it never overwrites an existing key or public file.
Keep generated private material outside the checkout.
