# Version History

## Intro

The version history is motivated by https://semver.org/ and https://keepachangelog.com/en/1.0.0/ .

NOTE: This project went from non-standard versioning to semver at some point. 

## Structure

Types of changes that can be seen in the changelog

```
Added: for new features/functionality.
Changed: for changes in existing features/functionality.
Deprecated: for soon-to-be removed features. Removed in the 
Removed: for now removed features.
Fixed: for any bug fixes.
Security: in case of vulnerabilities.
```

## How deprecation of functionality is handled?

tl;dr 1 minor release stating that the functionality is going to be deprecated. Then in the next major - removed.

```
Deprecating existing functionality is a normal part of software development and 
is often required to make forward progress. 

When you deprecate part of your public API, you should do two things: 

(1) update your documentation to let users know about the change, 
(2) issue a new minor release with the deprecation in place. 
Before you completely remove the functionality in a new major 
release there should be at least one minor release 
that contains the deprecation so that users can smoothly transition to the new API
```

As per https://semver.org/ .

As per rule-of-thumb, moving the project forward is very important, 
  but providing stability is the most important thing to anyone using `vaulted`.

Introducing breaking changes under a feature flag can be ok in some cases where new functionality needs user feedback before being introduced in next major release.

## Changelog

Change line format:

```
* <Change title/PR title/content> ; Ref: <pr link>
```

## Unreleased (master)

## v0.4.3

### Changed

* Build with Golang 1.15.x (1.15.8) ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/

## v0.4.2

### Fixed

* Fixed Alpine compatibility of binaries ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/commit/77bc612e46a074e7a1adbb8ebac377f79d7ba402

## v0.4.1

### Fixed

* Fixed lack of checks for provider attributes `private_key_content` and `private_key_path` ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/7
* Fixed Terraform provider SDK version not being compatible with terraform 0.12.x ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/7

## v0.4.0

### Changed

* Provider configuration attribute `private_key_content` ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/6

## v0.3.0

### Changed

* Updated to Terraform SDK 0.12.16

## v0.2.0

### Added

* Testing against Vault `1.1.1` ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/1

### Changed

* Updated to Vault (API) library to release v1.1.2 (latest) ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/1

### Removed

* Testing against Vault `1.1.0` ; Ref: https://github.com/sumup-oss/terraform-provider-vaulted/pull/1

## v0.1.0

### Added

* Project
* CI setup
* Documentation
