FROM ubuntu:19.10
ARG executable
COPY ${executable} /resolver
RUN chmod +x /resolver
ENV RUST_BACKTRACE=full
ENV RUST_LOG=info
EXPOSE 5353
ENTRYPOINT ["./resolver"]