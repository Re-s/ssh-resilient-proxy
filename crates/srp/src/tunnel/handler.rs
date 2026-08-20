//! russh 客户端 Handler：主机密钥校验与断连感知。

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use russh::client;
use russh::keys::ssh_key;
use tracing::{error, info, warn};

use super::config::HostKeyPolicy;
use super::manager::{accepts_unknown_host, fingerprint_matches};

/// 断连信号。Handler 在收到 SSH 断连时置位，管理器据此判定死链。
///
/// russh 的 `Handle::is_closed()` 只反映内部 mpsc 是否关闭，某些断连路径下
/// 它的置位会滞后。加上这个显式信号可以更快发现死链，缩短自愈时间。
#[derive(Debug, Default)]
pub struct DisconnectSignal(AtomicBool);

impl DisconnectSignal {
    pub fn trigger(&self) {
        self.0.store(true, Ordering::Release);
    }

    pub fn is_triggered(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

pub struct ClientHandler {
    host: String,
    port: u16,
    policy: HostKeyPolicy,
    known_hosts: Option<PathBuf>,
    disconnect: std::sync::Arc<DisconnectSignal>,
}

impl ClientHandler {
    pub fn new(
        host: String,
        port: u16,
        policy: HostKeyPolicy,
        known_hosts: Option<PathBuf>,
        disconnect: std::sync::Arc<DisconnectSignal>,
    ) -> Self {
        Self {
            host,
            port,
            policy,
            known_hosts,
            disconnect,
        }
    }

    /// 主机密钥校验的实际逻辑。
    ///
    /// 这里是整个程序最关键的安全边界：代理承载全部流量，一旦接受了
    /// 攻击者的主机密钥，所谓的"加密隧道"就是把明文直接递给中间人。
    /// 因此默认策略是严格拒绝，且任何"已记录但不匹配"的情况一律失败——
    /// 那正是中间人攻击的特征。
    fn verify(&self, key: &ssh_key::PublicKey) -> Result<bool, russh::Error> {
        let fp = key.fingerprint(Default::default()).to_string();

        match &self.policy {
            HostKeyPolicy::Pinned(pin) => {
                // 固定指纹模式不读 known_hosts，完全由配置决定。
                let ok = fingerprint_matches(pin, &fp);
                if !ok {
                    error!(
                        host = %self.host,
                        expected = %pin,
                        actual = %fp,
                        "host key does not match the pinned fingerprint; refusing to connect"
                    );
                }
                Ok(ok)
            }
            policy => {
                let known = match &self.known_hosts {
                    Some(p) => russh::keys::check_known_hosts_path(&self.host, self.port, key, p),
                    None => russh::keys::check_known_hosts(&self.host, self.port, key),
                };
                match known {
                    // 已记录且匹配。
                    Ok(true) => Ok(true),
                    // 主机未记录。
                    Ok(false) => {
                        if accepts_unknown_host(policy) {
                            warn!(
                                host = %self.host,
                                fingerprint = %fp,
                                "unknown host key accepted under accept_new policy; verify this fingerprint out-of-band"
                            );
                            let learned = match &self.known_hosts {
                                Some(p) => russh::keys::known_hosts::learn_known_hosts_path(
                                    &self.host, self.port, key, p,
                                ),
                                None => russh::keys::known_hosts::learn_known_hosts(
                                    &self.host, self.port, key,
                                ),
                            };
                            if let Err(e) = learned {
                                // 写不进 known_hosts 不阻止本次连接，但要让用户知道
                                // 下次仍会重新信任。
                                warn!(error = %e, "failed to record host key in known_hosts");
                            }
                            Ok(true)
                        } else {
                            error!(
                                host = %self.host,
                                fingerprint = %fp,
                                "host key is not in known_hosts and policy is strict; refusing to connect. \
                                 Verify the fingerprint, then add it or set host_key = \"accept_new\" once."
                            );
                            Ok(false)
                        }
                    }
                    // 已记录但**不匹配**：这是中间人攻击的典型特征，
                    // 任何策略下都必须拒绝，accept_new 也不例外。
                    Err(russh::keys::Error::KeyChanged { line }) => {
                        error!(
                            host = %self.host,
                            fingerprint = %fp,
                            known_hosts_line = line,
                            "HOST KEY CHANGED — refusing to connect. This may be a man-in-the-middle attack. \
                             If the server was legitimately rekeyed, remove the offending known_hosts line manually."
                        );
                        Ok(false)
                    }
                    Err(e) => {
                        error!(error = %e, "failed to check known_hosts; refusing to connect");
                        Ok(false)
                    }
                }
            }
        }
    }
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        self.verify(server_public_key)
    }

    async fn disconnected(
        &mut self,
        reason: client::DisconnectReason<Self::Error>,
    ) -> Result<(), Self::Error> {
        // 置位后管理器会在下一次巡检（或被显式唤醒时）立即重连。
        self.disconnect.trigger();
        match reason {
            client::DisconnectReason::ReceivedDisconnect(_) => {
                info!(host = %self.host, "server closed the ssh session");
                Ok(())
            }
            client::DisconnectReason::Error(e) => {
                warn!(host = %self.host, error = %e, "ssh session ended with an error");
                // 不把错误继续上抛：断连本身不是程序错误，自愈逻辑会接手。
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn disconnect_signal_latches() {
        let s = DisconnectSignal::default();
        assert!(!s.is_triggered());
        s.trigger();
        assert!(s.is_triggered());
        s.trigger();
        assert!(s.is_triggered(), "must stay latched");
    }

    fn handler(policy: HostKeyPolicy, known_hosts: Option<PathBuf>) -> ClientHandler {
        ClientHandler::new(
            "example.com".into(),
            22,
            policy,
            known_hosts,
            Arc::new(DisconnectSignal::default()),
        )
    }

    /// 测试用 RNG 适配器。
    ///
    /// `ssh_key::PrivateKey::random` 要求 rand_core **0.10** 的 `CryptoRng`，
    /// 而 workspace 里的 `rand` 0.9 用的是 rand_core 0.9——两套 trait 互不兼容。
    /// russh 也没有启用 ssh-key 的 `getrandom` feature，所以拿不到 `SysRng`。
    /// 实现 0.10 的 `TryRng<Error = Infallible>` 即可自动获得 `Rng` 与
    /// `CryptoRng`（见 rand_core 0.10 的 blanket impl）。
    struct TestRng;

    // `TryCryptoRng` 是纯标记 trait，rand_core 只为 `DerefMut` 提供 blanket impl，
    // 所以必须显式声明"这个 RNG 适合密码学用途"。
    impl ssh_key::rand_core::TryCryptoRng for TestRng {}

    impl ssh_key::rand_core::TryRng for TestRng {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            let mut b = [0u8; 4];
            self.try_fill_bytes(&mut b)?;
            Ok(u32::from_le_bytes(b))
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            let mut b = [0u8; 8];
            self.try_fill_bytes(&mut b)?;
            Ok(u64::from_le_bytes(b))
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            // 直接读操作系统熵源。测试里也不该用可预测的密钥。
            use std::io::Read as _;
            let mut f = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
            f.read_exact(dst).expect("read /dev/urandom");
            Ok(())
        }
    }

    fn a_key() -> ssh_key::PublicKey {
        let sk = ssh_key::PrivateKey::random(&mut TestRng, ssh_key::Algorithm::Ed25519)
            .expect("generate key");
        sk.public_key().clone()
    }

    #[test]
    fn strict_policy_rejects_unknown_host() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        std::fs::write(&kh, "").unwrap();

        let h = handler(HostKeyPolicy::Strict, Some(kh));
        assert!(
            !h.verify(&a_key()).unwrap(),
            "strict must refuse hosts it has never seen"
        );
    }

    #[test]
    fn accept_new_learns_then_strict_accepts_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        std::fs::write(&kh, "").unwrap();
        let key = a_key();

        let h = handler(HostKeyPolicy::AcceptNew, Some(kh.clone()));
        assert!(h.verify(&key).unwrap(), "accept_new must accept and learn");

        let content = std::fs::read_to_string(&kh).unwrap();
        assert!(
            content.contains("example.com"),
            "host key must be recorded: {content:?}"
        );

        // 同一个密钥在严格模式下现在应当通过。
        let h = handler(HostKeyPolicy::Strict, Some(kh.clone()));
        assert!(h.verify(&key).unwrap(), "learned key must satisfy strict");

        // 换一个密钥则必须被拒（KeyChanged 路径）。
        let h = handler(HostKeyPolicy::Strict, Some(kh.clone()));
        assert!(
            !h.verify(&a_key()).unwrap(),
            "a different key for a known host must be refused"
        );
    }

    /// 已记录的主机换了密钥时，即使策略是 accept_new 也必须拒绝。
    #[test]
    fn accept_new_still_refuses_changed_host_key() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        std::fs::write(&kh, "").unwrap();

        let h = handler(HostKeyPolicy::AcceptNew, Some(kh.clone()));
        assert!(h.verify(&a_key()).unwrap());

        let h = handler(HostKeyPolicy::AcceptNew, Some(kh));
        assert!(
            !h.verify(&a_key()).unwrap(),
            "accept_new must not silently accept a changed host key"
        );
    }

    #[test]
    fn pinned_policy_matches_only_the_pinned_fingerprint() {
        let key = a_key();
        let fp = key.fingerprint(Default::default()).to_string();

        let h = handler(HostKeyPolicy::Pinned(fp.clone()), None);
        assert!(h.verify(&key).unwrap(), "matching pin must be accepted");

        let h = handler(HostKeyPolicy::Pinned("SHA256:bogus".into()), None);
        assert!(!h.verify(&key).unwrap(), "wrong pin must be refused");

        // 固定指纹模式不读 known_hosts：即使路径完全不存在，
        // 匹配的密钥仍应通过，不匹配的仍应被拒。
        let h = handler(
            HostKeyPolicy::Pinned(fp.clone()),
            Some(PathBuf::from("/nonexistent/known_hosts")),
        );
        assert!(
            h.verify(&key).unwrap(),
            "pinned mode must not depend on known_hosts being readable"
        );

        let h = handler(
            HostKeyPolicy::Pinned(fp),
            Some(PathBuf::from("/nonexistent/known_hosts")),
        );
        assert!(
            !h.verify(&a_key()).unwrap(),
            "a different key must still be refused in pinned mode"
        );
    }

    /// known_hosts 不可读（不存在、是目录、无权限）时，russh 的
    /// `check_known_hosts_path` 返回 `Ok(false)`（视作"未记录"）而不是 `Err`。
    /// 所以这条路径的安全性完全取决于 strict 策略拒绝未知主机——
    /// 这个测试锁定该行为，防止有人日后把 strict 的默认分支改成放行。
    #[test]
    fn unreadable_known_hosts_never_means_trusted_under_strict() {
        let dir = tempfile::tempdir().unwrap();
        for path in [
            // 是目录，打开后读取失败
            dir.path().to_path_buf(),
            // 完全不存在
            dir.path().join("does-not-exist"),
        ] {
            let h = handler(HostKeyPolicy::Strict, Some(path.clone()));
            assert!(
                !h.verify(&a_key()).unwrap(),
                "an unreadable known_hosts ({path:?}) must never mean 'trusted'"
            );
        }
    }

    /// 已记录主机的密钥被替换时，`check_known_hosts_path` 返回
    /// `Err(KeyChanged)`，必须被识别为拒绝而不是被当成一般 IO 错误。
    #[test]
    fn changed_key_is_refused_with_a_distinct_path() {
        let dir = tempfile::tempdir().unwrap();
        let kh = dir.path().join("known_hosts");
        std::fs::write(&kh, "").unwrap();

        // 先学习一个密钥。
        let first = a_key();
        let h = handler(HostKeyPolicy::AcceptNew, Some(kh.clone()));
        assert!(h.verify(&first).unwrap());

        // 同算法的另一个密钥 → KeyChanged。
        let second = a_key();
        assert_eq!(
            first.algorithm(),
            second.algorithm(),
            "both keys must be Ed25519 for this to hit the KeyChanged path"
        );
        for policy in [HostKeyPolicy::Strict, HostKeyPolicy::AcceptNew] {
            let h = handler(policy.clone(), Some(kh.clone()));
            assert!(
                !h.verify(&second).unwrap(),
                "changed host key must be refused under {policy:?}"
            );
        }
    }
}
