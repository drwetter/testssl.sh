## Usage:
```
docker run --user=nobody -t testssl.sh example.com
```

Or pull image from docker hub, then run:
```
docker run --user=nobody -t drwetter/testssl.sh example.com
```

This is a experimental version with Debian Linux. Don\'t rely on it!
Things will break.

Besides the "latest" branch supported tags are currently "2.9dev" (equal to "latest"), and
"2.9.5" = "stable": ``docker run -t drwetter/testssl.sh:stable example.com``.
