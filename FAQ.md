# Frequently asked questions

## The terraform secrets I put are encrypted in the git repository, but what about the terraform state - local and external? Are they leaking plaintext somewhere?

`terraform-provider-vaulted` takes extreme care never to put into `stdout` and `terraform.tfstate` neither in local state nor in remote, any plaintext values.

Your secrets are only put (`set` in terraform API terms) into the terraform state with their encrypted presentation.

**When comparing terraform resource values against external Vault to synchronize state, they're never put into decrypted (plaintext) state. 
Only in memory they're temporarily plaintext.**

## I've applied my secrets via `terraform`, but someone deleted them from Vault. What now?

When you run `terraform plan` or `terraform apply` your `vaulted_vault_secret` resources will 
 verify that their decrypted content is present in the external Vault. 
 If they're missing, it'll show up as `deleted` resources in terraform diff.

Once you run `terraform apply` they're going to be present once again.

## I've rotated my secrets via `vaulted` and now want to `terraform apply` them. What will happen?

When you run `terraform plan` you're going to see terraform state difference. 

`terraform apply` and the state will be updated. The external Vault secret will remain the same.

## I've rekeyed my secrets via `vaulted` and now want to `terraform apply` them. What will happen?

When you run `terraform plan` you're going to see terraform state difference. 

`terraform apply` and the state will be updated. The external Vault secret will remain the same.
