# Use cases

* providing first-class Vault encrypted resources,
* **extremely** secure measures to never **log**, **store** plaintext values in terraform state, stdout or stderr. (If there are such exceptions, email/message maintainer),
* ease-to-use Vault encrypted resources in plain-simple terraform.
* provides necessary security tools to `rotate` or `rekey` secrets.

## Security measures

* **Don't** commit your private key in your git repository.
* **Commit** your public key in your git repository. **This enable everyone to be able to provide new secrets, but only authorized people/systems will be able to decrypt, see and apply them**
* Store your private key in password manager such as LastPass, Keeper, 1Password, etc.

## Rotating secrets

This is applicable when you're worried that your secrets might have been cracked.

**This does not mean that your private key has been exposed**.

Follow [USAGE](./USAGE.md)'s `Rotating secrets`.

## Rekeying secrets

This is applicable when you're worried that your **private key has been exposed**.

You "rekey" and change the keypair and secrets.

Follow [USAGE](./USAGE.md)'s `Rekeying secrets`.

