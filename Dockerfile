# 多阶段构建：编译 SKF 动态库，输出到共享 volume 供其他容器使用
FROM rust:1.75-slim AS builder

WORKDIR /app

# 预先拉取依赖（利用缓存层）
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'pub fn _placeholder(){}' > src/lib.rs \
    && cargo build --release \
    && rm -rf src

# 复制完整源码并编译动态库
COPY src/ ./src/
RUN touch src/lib.rs && cargo build --release

# ── 产物阶段 ────────────────────────────────
# 精简镜像仅保留编译产物，容器启动时将 .so 复制到共享 volume
FROM debian:bookworm-slim

WORKDIR /opt/mock-libs

COPY --from=builder /app/target/release/libskf_mock.so ./

# Reason: 作为 init 容器使用，完成文件复制后即退出。
# docker-compose 中配合 volumes 将 .so 共享给其他容器
CMD ["sh", "-c", "echo 'libskf_mock.so ready at /opt/mock-libs/' && ls -lh /opt/mock-libs/"]
