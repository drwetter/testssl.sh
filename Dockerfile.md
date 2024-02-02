## Usage

### From git directory

```
docker build .
```

Catch is when you run without image tags you need to catch the ID when building

```
[..]
---> 889fa2f99933
Successfully built 889fa2f99933
```

More comfortable is

```
docker build -t mytestssl .
docker run --rm -t mytestssl example.com
```

You can also supply command line options like:

```
docker run -t mytestssl --help
docker run --rm -t mytestssl -p --header example.com
```

### From dockerhub

You can pull the image from dockerhub and run:

```
docker run --rm -t drwetter/testssl.sh --fs example.com
```

Supported tags are: ``3.2`` and ``latest``, which are the same, i.e. the rolling release. ``3.0`` is the latest stable version from git which might have a few improvements (see git log) over the released version 3.0.X.

``docker run --rm -t drwetter/testssl.sh:stable example.com``.

Keep in mind that any output file (--log, --html, --json etc.) will be created within the container. If you wish to have this created in a local directory on your host you can mount a volume into the container and change the output prefix where the container user has write access to, e.g.:

```
docker run --rm -t -v /tmp:/data drwetter/testssl.sh --htmlfile /data/ example.com
```

which writes the HTML output to ``/tmp/example.com_p443-<date>-<time>.html.`` The uid/gid is the one from the docker user. Normally the file is 644. testssl.sh's docker container uses a non-root user (usually with user/groupid 1000:1000).
