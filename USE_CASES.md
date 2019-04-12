# Use cases

* providing first-class Vault encrypted resources,
* **extremely** secure measures to never **log**, **store** plaintext values in terraform state, stdout or stderr. (If there are such exceptions, email/message maintainer),
* ease-to-use Vault encrypted resources in plain-simple terraform.
* provides necessary security tools to `rotate` or `rekey` secrets.

## Simple integration approach

1. Generate RSA keypair by following https://github.com/sumup-oss/vaulted#setup
1. Specify `provider` by following https://github.com/sumup-oss/terraform-provider-vaulted/blob/master/USAGE.md#provider
1. Add `vaulted_vault_secret` resources by following https://github.com/sumup-oss/terraform-provider-vaulted/blob/master/USAGE.md#new-resource
1. `terraform plan`
1. `terraform apply`
1. :tada:

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

