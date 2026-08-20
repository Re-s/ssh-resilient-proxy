/// 一个最小的 russh 客户端回调实现。
///
/// 默认构造函数 [`Self::accept_any_host_key`] 适合纯网络故障测试；
/// [`Self::expect_host_key`] 则严格比较服务器主机公钥，适合验证 host key 的测试。
#[derive(Clone, Debug)]
pub struct TestClientHandler {
    expected_host_key: Option<russh::keys::PublicKey>,
}

impl TestClientHandler {
    /// 构造一个接受任意服务器主机密钥的 handler。
    pub fn accept_any_host_key() -> Self {
        Self {
            expected_host_key: None,
        }
    }

    /// 构造一个只接受指定服务器主机密钥的 handler。
    pub fn expect_host_key(host_key: russh::keys::PublicKey) -> Self {
        Self {
            expected_host_key: Some(host_key),
        }
    }
}

impl russh::client::Handler for TestClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        // 未指定期望公钥时接受任意主机密钥；指定了就严格比较。
        Ok(match self.expected_host_key.as_ref() {
            Some(expected) => expected == server_public_key,
            None => true,
        })
    }
}
