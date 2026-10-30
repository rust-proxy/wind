# Quiche ECH

服务端通过 `CertStore::with_ech_key(config, private_key)` 设置二进制 ECHConfig 与原始 X25519 私钥，并把该 store 交给 `bind_server` / `bind_server_with_socket`。密钥必须与配置中的公钥匹配。`CertStore::update` 只更新证书，保留 ECH 密钥。

客户端通过 `ClientTlsConfig::ech_config_list` 提供二进制 ECHConfigList；默认是 `None`。`wind-tuic` 的 `TuicheOutboundOpts` 和 `TuicheOutboundBuilder::ech_config_list` 转发该配置，包含重连路径。使用结构体字面量的消费者需要显式补上 `ech_config_list: None`，或使用构造器。

ECH 是独立于证书验证的可选机制。设置后客户端只有在 BoringSSL 确认 ECH 已接受时才会拿到连接句柄；无可用配置或拒绝均失败，应用数据无法进入非 ECH 连接。不自动采用服务器提供的 retry configs。Quinn 配置路径当前明确拒绝该字段。

`forks/quiche` 中 tokio-quiche 的握手前 SSL hook 用于设置客户端 ECH。服务端 hook 的配置失败会向上传播，不能退回默认 TLS 上下文；原有证书热重载 callback 继续使用。需要同时使用本地 fork 和 Wind 改动，发布时先发布依赖再更新消费者固定 revision。

完整应用 E2E 和拒绝测试位于相邻 TUIC 仓库 `crates/tuic-tests/tests/{e2e,integration}/ech.rs`。普通 QUIC、0-RTT 与证书热重载回归仍使用既有测试。
