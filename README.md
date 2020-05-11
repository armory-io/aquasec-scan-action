# Aquasec Security Scan

This requires using a user who can call the APIs.  Specific permissions are out of scope for this image.  It triggers the scan using the v1 API as the v2 api doesn't support scanning as of this creation.

## Inputs
None yet - see usage below for required parameters.  PR's welcome :) 

## Example Usage

```
uses: actions/aquasec-scan-action@v0.0.1
with:
    username: ${{ secrets.AQUA_USER }}
    password: ${{ secrets.AQUA_PASSWORD }}
    ## URL for aquasec CSP
    url: https://aquasec.example.com
    ## The image name, aka armory/debugging-tools
    image: package/repo
    ## The registry as configured in your aquasec CSP
    registry: Artifactory
```
