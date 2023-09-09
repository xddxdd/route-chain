FROM alpine:edge AS step_0
WORKDIR /root
COPY . .
RUN apk add --no-cache build-base linux-headers
RUN make static

################################################################################

FROM scratch AS step_1
ENV PATH=/
COPY --from=step_0 /root/route-chain /
ENTRYPOINT ["/route-chain"]
