## Usage:

(in git directory):
```
docker build -t mytestssl .
docker run --rm -t mytestssl example.com
```

You can also supply command line options like:

```
docker run -t mytestssl --help
docker run --rm -t mytestssl -p --header example.com
```

or pull the image from dockerhub and run:

```
docker run --rm -t drwetter/testssl.sh --pfs example.com
```

Tags supported are: ``latest``, ``stable`` which _for now_ are all the same and point to ``3.0``.

``docker run --rm -t drwetter/testssl.sh:stable example.com``.

And for the indomitable users who prefer to run old stuff you can use the tag ``2.9.5``. Please note ``2.9dev`` should not be used anymore.

Keep in mind that any output file (--log, --html, --json etc.) will be created in the container. If you wish to have this created in a local directory you can mount a volume into the container and change the output prefix where the container user has write access to, e.g.:

```
docker run --rm -t -v /tmp:/data drwetter/testssl.sh --htmlfile /data/ example.com
```

which writes the output to ``/tmp/example.com_p443-<date>-<time>.html.`` The uid/gid is the one from the docker user but normally the file is 644. testssl.sh's docker container uses a non-root user (usually with user/groupid 1000:1000).
