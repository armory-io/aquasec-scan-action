# Aquasec Security Scan

This requires using a user who can call the APIs.  Specific permissions are out of scope for this image.  It triggers the scan using the v1 API as the v2 api doesn't support scanning as of this creation.

## Inputs
None yet - see usage below for required parameters.  PR's welcome :) 

## Example Usage

### Default Usage

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

### Customize Github PR comment message

```yaml
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
    commentTemplate: |
      :skull: Security Scan Results :skull:
      Found {{ .Scan.CriticalVulns }} Critical Vulnerabilities
      Found {{ .Scan.HighVulns }} High Vulnerabilities
      
      See [scan details]({{ .AquasecHtmlImageUrl }}) for more information.
        
```

Available Template Properties

```
Registry            string
Image               string
AquasecBaseUrl      string
Scan                ScanData (CriticalVulns, HighVulns, MediumVulns, LowVulns)
ImageName           string
ImageTag            string
// AquasecHtmlImageUrl is a convenience property for linking directly to the image in the browser
AquasecHtmlImageUrl string
```

