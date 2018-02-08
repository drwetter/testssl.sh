## Usage:

(in git directory):
```
docker build -t mytestssl .
docker run -t mytestssl example.com
```

You can also supply command line options like:

``docker run -t mytestssl -p --header example.com``

Please keep in mind that any output file (--log, --html, --json etc.) will be created
in the container.


You can also pull the image from docker hub, then run:
```
docker run -t drwetter/testssl.sh --pfs example.com
```

Also if you don't provide a user, this docker container uses
a non-root user.

This is an experimental version with Alpine Linux. Don\'t rely on it!

Besides the "latest" branch supported tags are currently "2.9dev" (equal to "latest"), and
"2.9.5" = "stable": ``docker run -t drwetter/testssl.sh:stable example.com``.
