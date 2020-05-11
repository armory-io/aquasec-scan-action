# Armory Aquasec Scan

## Inputs

## Example Usage

```
uses: actions/aquasec-scan-action@v0.0.1
with:
    username: ${{ secrets.AQUA_USER }}
    password: ${{ secrets.AQUA_PASSWORD }}
    url: https://aquasec.armory.io
    image: built-image-name
    registry: Artifactory/image/armory
```