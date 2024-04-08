# yara-scanner

## Build

### Build image

`sudo docker build -t yara-scanner-image .`

### Run container

`sudo docker run -v $(pwd)/src:/opt/src -v $(pwd)/vol:/opt/vol --rm yara-scanner-image`

### Yara rules

https://yarahq.github.io/

## Example run

`yara-scanner -rule rules.yar -processes -exclude /var/lib/postgres`
