# Distroless static + nonroot keeps the attack surface minimal — no shell,
# no package manager, runs as UID 65532. The binary is built and copied in
# by GoReleaser, so this Dockerfile is intentionally a copy-only stage.
FROM gcr.io/distroless/static:nonroot

COPY kubesplaining /usr/local/bin/kubesplaining

USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/kubesplaining"]
