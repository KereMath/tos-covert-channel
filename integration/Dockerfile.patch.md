# Dockerfile changes against upstream

The sender and the receiver run inside the upstream `sec` and `insec` hosts,
which do not ship Scapy. One line is appended to each of the two upstream
files — `dockers/sec/Dockerfile` and `dockers/insec/Dockerfile`:

```dockerfile
RUN apt update && apt install -y python3-scapy
```

The detector and the mitigator need no image change: they run inside the
upstream `python-processor` container, which already has `nats-py` and Scapy.

The Phase 1 delay processor needs its own image, and that file is included in
this repository at `dockers/random-delay-processor/Dockerfile` — copy it into
the same path in your middlebox checkout.
