### Naming scheme

* 00-05:  Does the bare testssl.sh work at all?
* 06-09:  Does the reporting work at all?
* 20-39:  Do scans work fine (client side)?
* 50-69:  Are the results what I expect (server side)?

Please help to write Travis/CI tests! Documentation can be found [here](https://perldoc.perl.org/Test/More.html).
You can consult the existing code here. Feel free to use `20_baseline_ipv4_http.t` or `23_client_simulation.t` as a
template.
