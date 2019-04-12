# Release process

Travis CI is used as a backbone to get releases going.

It's currently using a secure Github API OAuth token with `public_repo` 
 permissions bound to https://github.com/syndbg .
 
## Rules

1. Releases are only created from `master`.
1. `master` is meant to be stable, so before tagging and create a new release, make sure that the CI checks pass.
1. Releases are GitHub releases.
1. Releases are following *semantic versioning*.
1. Releases are to be named in pattern of `vX.Y.Z`. The produced binary artifacts contain the `vX.Y.Z` in their names.
1. Changelog must up-to-date with what's going to be released. Check [CHANGELOG](./CHANGELOG.md).

## Flow

1. Create a new GitHub release using https://github.com/sumup-oss/terraform-provider-vaulted/releases/new
1. `Tag Version` and `Release Title` are going to be in pattern of `vX.Y.Z`.
1. `Describe this release` (content) is going to link the appropriate [CHANGELOG](./CHANGELOG.md) entry.
1. Wait for Travis CI to pass checks
1. Wait for the produced artifacts to be uploaded at `https://github.com/sumup-oss/terraform-provider-vaulted/releases/tag/<vX.Y.Z>`

