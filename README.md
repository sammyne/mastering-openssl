# OpenSSL 示例程序

##  环境依赖

- openssl-1.1.1k

> 建议在 [Dockerfile](./docker/Dockerfile) 内开发测试。

## 快速开始

```bash
cmake -B build
cmake --build build -j
```

## 示例程序

### 加密相关功能

此部分示例程序均位于 crypto 文件夹。

程序 | 说明
----:|:-----
sm2/sign_then_verify.cc  | SM2 算法签名、验签
x509/verify_cert_chain.cc | 验证证书链

### EVP

- [ ] [sm2_sign_vrf_test.cpp](crypto/evp/sm2_sign_vrf_test.cpp)
  - SM3 isn't support
