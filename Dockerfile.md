## Usage:

(in git directory):
```
docker build -t mytestssl .
docker run -t mytestssl example.com
```

You can also supply command line options like:

``docker run -t mytestssl -p --header example.com``

Please keep in mind that any output file (--log, --html, --json etc.) will be created
in the container. Also if you don't provide a user, this docker container uses a non-root user.


You can also pull the image from dockerhub and run:
```
docker run -t drwetter/testssl.sh --pfs example.com
```

Tags supported are currently: ``latest``, ``stable`` which are all the same and point to ``3.0``. And for the indomitable users who prefer to run old stuff ``2.9.5``. The tag ``2.9dev`` should not be used.

``docker run -t drwetter/testssl.sh:stable example.com``.
