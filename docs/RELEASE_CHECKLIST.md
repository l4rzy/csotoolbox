# Release checklist

Before publishing source or release artifacts:

- Review every source file and asset for personal information, organization details, secrets, generated binaries, and third-party license requirements.
- Build the client and server from a clean checkout and run the checks listed in the README.
- Confirm the client project version, release tag, and server version agree.
- Verify the committed certificate pin matches the certificate intended for the release client; keep the private key out of the repository.
- Verify each release manifest filename, version, checksum, and size against the artifacts being published.
- Push the version tag and confirm the Windows and Linux x64 release assets are attached to the GitHub release.
- Document supported platforms, known limitations, and any upstream service requirements.
